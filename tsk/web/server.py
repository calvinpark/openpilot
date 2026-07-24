#!/usr/bin/env python3
import json
import mimetypes
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from tsk.lib.collect_can import collect as collect_can, count_oracle_frames, oracle_path as can_oracle_path, PROTECTED_TARGET, SYNC_TARGET
from tsk.lib.dump_dataflash import DUMP_TOTAL, dump as dump_dataflash, dump_path
from tsk.lib.env import is_agnos, setup
from tsk.lib.extractor import NotAGNOSError, RetryError, TSKExtractor
from tsk.lib.key_file_manager import KeyFileManager, format_key
from tsk.lib.matcher import run as run_matcher
from tsk.lib.reboot_manager import REBOOT_ACTIONS, RebootManager
from tsk.lib.sniff_can import sniff as sniff_can, summarize_counts
from tsk.lib.dump_diag import diagnose as dump_diagnose
from tsk.lib.prog_probe import probe_programming
from tsk.lib.read_mem import read_key_region
from tsk.lib.ident_map import map_surface
from tsk.lib.reset_probe import probe_reset_window
from tsk.lib.level3_probe import probe_level3
from tsk.lib.sendkey_probe import send_willem_key
from tsk.lib.preamble_probe import probe_preamble
from tsk.lib.sweep_uds import sweep
from tsk.lib.capture_ready import capture_ready


HOST = "0.0.0.0"
PORT = 11111
ASSET_DIR = Path(__file__).resolve().with_name("static")
OFFROAD_ALERT_PARAM = "Offroad_NoFirmware"
OFFROAD_ALERT_INTERVAL = 5.0

# Shared tail for the unexpected-error surfaces (extract + match). The leading
# "!!!!" makes index.html's modal render it red; the extractor terminal prints it
# verbatim. Kept in one place so the two paths can't drift.
PING_REPORT = ("!!!! Unexpected error. Please take a screenshot, post it on "
               "#toyota-security, and ping @calvinspark")

last_alert_url: str | None = None
# One physical panda: extract, dump, and collect must not run concurrently. Held
# for the whole operation (extract in the request thread; dump/collect in their
# job threads, released in the job's finally).
panda_lock = threading.Lock()
matcher_lock = threading.Lock()


def append_address(addresses: list[str], ip: str) -> None:
  if ip and not ip.startswith("127.") and ip not in addresses:
    addresses.append(ip)


def get_ipv4_addresses() -> list[str]:
  addresses: list[str] = []

  try:
    output = subprocess.check_output(
      ["ip", "-o", "-4", "route", "get", "1.1.1.1"],
      encoding="utf-8",
      stderr=subprocess.DEVNULL,
      timeout=1.0,
    )
    parts = output.split()
    if "src" in parts:
      append_address(addresses, parts[parts.index("src") + 1])
  except (OSError, subprocess.SubprocessError, TimeoutError):
    pass

  try:
    for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
      append_address(addresses, info[4][0])
  except OSError:
    pass

  # AGNOS devices have the `ip` utility, and it tends to be more accurate than
  # hostname lookups for hotspot and garage Wi-Fi testing.
  try:
    output = subprocess.check_output(
      ["ip", "-o", "-4", "addr", "show", "scope", "global"],
      encoding="utf-8",
      stderr=subprocess.DEVNULL,
      timeout=1.0,
    )
    for line in output.splitlines():
      parts = line.split()
      if "inet" not in parts:
        continue

      cidr = parts[parts.index("inet") + 1]
      append_address(addresses, cidr.split("/", 1)[0])
  except (OSError, subprocess.SubprocessError, TimeoutError):
    pass

  return addresses


def get_tsk_url() -> str | None:
  addresses = get_ipv4_addresses()
  return f"http://{addresses[0]}:{PORT}" if addresses else None


def get_params_dir() -> Path:
  params_root = Path(os.getenv("PARAMS_ROOT", "/data/params"))
  params_prefix = os.getenv("OPENPILOT_PREFIX", "d") or "d"
  return params_root / params_prefix


def get_reboot_actions_payload() -> dict:
  reboot_manager = RebootManager()
  payload = {
    "is_agnos": is_agnos(),
    "dry_run": not reboot_manager.is_agnos,
  }
  payload.update(reboot_manager.actions_payload())
  return payload


def run_reboot_action(action: str) -> tuple[HTTPStatus, dict]:
  if action not in REBOOT_ACTIONS:
    return HTTPStatus.BAD_REQUEST, {
      "ok": False,
      "error": "bad_action",
      "title": "Unknown action",
      "message": f"Unknown reboot action: {action}",
      **RebootManager.key_status_payload(),
    }

  try:
    return HTTPStatus.OK, RebootManager().execute(action)
  except Exception as e:
    return HTTPStatus.INTERNAL_SERVER_ERROR, {
      "ok": False,
      "error": "unexpected",
      "title": "Unexpected error",
      "message": str(e),
      "traceback": traceback.format_exc(),
      **RebootManager.key_status_payload(),
    }


def write_offroad_alert(url: str | None) -> bool:
  params_dir = get_params_dir()
  if not params_dir.exists():
    return False

  alert_path = params_dir / OFFROAD_ALERT_PARAM
  if url is None:
    try:
      alert_path.unlink()
    except FileNotFoundError:
      pass
    return True

  payload = json.dumps({"text": "%1", "severity": 0, "extra": url}, sort_keys=True)
  tmp_path = params_dir / f".tmp_{OFFROAD_ALERT_PARAM}_{os.getpid()}"

  with open(tmp_path, "w", encoding="utf-8") as f:
    f.write(payload)
    f.flush()
    os.fsync(f.fileno())

  os.replace(tmp_path, alert_path)

  try:
    dir_fd = os.open(params_dir, os.O_RDONLY)
    try:
      os.fsync(dir_fd)
    finally:
      os.close(dir_fd)
  except OSError:
    pass

  return True


def update_offroad_alert() -> None:
  global last_alert_url

  url = get_tsk_url()
  # The manager wipes Offroad_NoFirmware on start (CLEAR_ON_MANAGER_START) and on
  # the onroad transition, out from under us. Rewrite when the URL changed or the
  # file is gone — trusting last_alert_url alone masks the deletion and the alert
  # never returns.
  alert_path = get_params_dir() / OFFROAD_ALERT_PARAM
  if url == last_alert_url and (url is None or alert_path.exists()):
    return

  try:
    if write_offroad_alert(url):
      last_alert_url = url
  except OSError as e:
    print(f"TSK Manager Web could not update offroad alert: {e}", flush=True)


def offroad_alert_loop() -> None:
  while True:
    update_offroad_alert()
    time.sleep(OFFROAD_ALERT_INTERVAL)


def resolve_asset(path: str) -> Path | None:
  relative_path = "index.html" if path in ("", "/") else unquote(path).lstrip("/")
  if relative_path.endswith("/"):
    relative_path += "index.html"

  relative = Path(relative_path)
  if relative.is_absolute() or ".." in relative.parts:
    return None

  candidate = (ASSET_DIR / relative).resolve()
  try:
    candidate.relative_to(ASSET_DIR.resolve())
  except ValueError:
    return None

  if candidate.is_file():
    return candidate

  return None


def content_type_for(path: Path) -> str:
  content_type, _ = mimetypes.guess_type(path.name)
  content_type = content_type or "application/octet-stream"
  if content_type.startswith("text/") or content_type in ("application/javascript", "application/json"):
    content_type += "; charset=utf-8"
  return content_type


DRY_RUN_FAKE_KEY = "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"
dry_run_counter = 0

# CAN collection runs as a background job, mirroring the DataFlash job below.
# can_state is the live progress the status endpoint reports; the collect thread
# owns writes under can_lock. ready == (status == "complete").
can_lock = threading.Lock()
can_state = {
  "ready": False,
  "status": "idle",   # idle | running | complete | insufficient | failed
  "sync_count": 0,
  "protected_count": 0,
  "seconds": 0.0,
  "message": "",
}

# DataFlash dump runs as a background job. df_state is the live progress the
# status endpoint reports; the dump thread owns writes to it under df_lock.
# ready == (status == "complete") so the UI's existing green-dot gating holds.
df_lock = threading.Lock()
df_state = {
  "ready": False,
  "status": "idle",   # idle | running | complete | partial | key_missed | failed
  "frames": 0,
  "bytes": 0,
  "total": DUMP_TOTAL,
  "message": "",
  "size": 0,
}

# CAN sniffer runs as a background job like the others. Read-only diagnostic: it
# tallies raw traffic per bus and writes no file, so there is nothing to rehydrate.
sniff_lock = threading.Lock()
sniff_state = {
  "status": "idle",   # idle | running | complete | failed
  "seconds": 0.0,
  "frames": 0,
  "bus_count": 0,
  "total": 0,
  "buses": [],
  "markers": [],
  "fd_buses": [],
  "message": "",
}

# Instrumented DataFlash dump (diagnostics). Runs the dump flow step by step and holds
# the full per-step log, EPS identity, and any traceback, for triaging an unknown EPS.
diag_lock = threading.Lock()
diag_state = {
  "status": "idle",   # idle | running | dumped | no_frames | rejected | failed
  "step_count": 0,
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "identity": [],
  "steps": [],
  "failed_at": "",
  "exception": "",
  "traceback": "",
  "frames": 0,
  "bytes": 0,
  "message": "",
}

# Programming-session entry probe. Tries several ways to enter the PROGRAMMING session
# on the EPS the sweep finds, and holds the per-sequence outcomes + the security result.
probe_lock = threading.Lock()
probe_state = {
  "status": "idle",   # idle | running | entered | blocked | unreachable | failed
  "attempt_count": 0,
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "attempts": [],
  "security": {},
  "security_levels": [],
  "did_it_take": {},
  "all_bus": [],
  "message": "",
}

# ReadMemoryByAddress (0x23) probe — direct read of the key region, no programming.
readmem_lock = threading.Lock()
readmem_state = {
  "status": "idle",   # idle | running | read | denied | unreachable | failed
  "count": 0,
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "reads": [],
  "message": "",
}

# EPS identity + read-only service-surface map.
ident_lock = threading.Lock()
ident_state = {
  "status": "idle",   # idle | running | mapped | unreachable | failed
  "count": 0,
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "identity": [],
  "services": [],
  "message": "",
}

# Reset-window probe — hard reset, then hammer PROGRAMMING through the reboot.
reset_lock = threading.Lock()
reset_state = {
  "status": "idle",   # idle | running | entered | blocked | unreachable | failed
  "count": 0,
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "reset": "",
  "attempts": [],
  "session_after": "",
  "message": "",
}

# Level 0x03 seed isolation probe — seed-only (no key sent), safe to re-run.
level3_lock = threading.Lock()
level3_state = {
  "status": "idle",   # idle | running | reproduced | conditional | no_seed | unreachable | failed
  "count": 0,
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "tests": [],
  "seeds": [],
  "primer": "",
  "message": "",
}

# Send-key probe — one Willem key at level 0x03/0x04.
sendkey_lock = threading.Lock()
sendkey_state = {
  "status": "idle",   # idle | running | unlocked | invalid_key | locked | denied | rejected | no_seed | unreachable | failed
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "session": "",
  "seed": "",
  "key": "",
  "send_key": "",
  "post_unlock_reads": [],
  "message": "",
}

# Pre-programming preamble probe — lock read + exploit-surface refusal codes + the 0x85/0x28
# preamble variants + a DTC diff. No key sent, no attempt counter touched.
preamble_lock = threading.Lock()
preamble_state = {
  "status": "idle",   # idle | running | security_open | programming_open | locked | blocked | dropped_out | unreachable | failed
  "count": 0,
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "identity": [],
  "lock": {},
  "services": [],
  "variants": [],
  "dtc": {},
  "reads": [],
  "liveness": "",
  "message": "",
}

# Exhaustive UDS sweep (Not Ready to Drive) — every service byte, every sub-function,
# deadline-bounded and resumable across runs.
sweep_lock = threading.Lock()
sweep_state = {
  "status": "idle",   # idle | running | complete | partial | unreachable | failed
  "count": 0,
  "last": "",
  "stage": "",
  "panda": "",
  "eps_bus": -1,
  "timeout_ms": 0,
  "stages": [],
  "answering": [],
  "silent": [],
  "responders": [],
  "records": 0,
  "frontier": "",
  "message": "",
}

# READY pass — full-payload capture + the mode diff driven by the sweep's work-list.
ready_lock = threading.Lock()
ready_state = {
  "status": "idle",   # idle | running | captured | no_sweep | unreachable | failed
  "count": 0,
  "last": "",
  "stage": "",
  "panda": "",
  "eps_bus": -1,
  "capture": {},
  "diff": [],
  "responders": [],
  "cross": [],
  "seeds": [],
  "frames": 0,
  "message": "",
}


def _df_progress(status=None, frames=None, bytes_done=None, total=None, message=None) -> None:
  with df_lock:
    if status is not None:
      df_state["status"] = status
    if frames is not None:
      df_state["frames"] = frames
    if bytes_done is not None:
      df_state["bytes"] = bytes_done
    if total is not None:
      df_state["total"] = total
    if message is not None:
      df_state["message"] = message


def _run_dataflash_mock() -> None:
  # Laptop dry run: ramp progress over a couple of seconds so the collector page
  # shows movement, then land on complete. The partial/key_missed paths only happen
  # on a real device.
  for done in (4096, 8192, 16384, 24576, DUMP_TOTAL):
    time.sleep(0.4)
    _df_progress(status="running", frames=done // 4, bytes_done=done, total=DUMP_TOTAL)
  with df_lock:
    df_state.update(status="complete", frames=DUMP_TOTAL // 4, bytes=DUMP_TOTAL,
                    total=DUMP_TOTAL, size=DUMP_TOTAL, ready=True,
                    message=f"Dump complete: {DUMP_TOTAL} bytes (mock).")


def _run_dataflash_job() -> None:
  try:
    result = dump_dataflash(progress_cb=_df_progress)
    status = result.get("status", "failed")
    with df_lock:
      df_state.update(
        status=status,
        frames=result.get("frames", df_state["frames"]),
        bytes=result.get("bytes", df_state["bytes"]),
        total=result.get("total", DUMP_TOTAL),
        message=result.get("message", ""),
        ready=(status == "complete"),
        size=result.get("bytes", 0) if status == "complete" else 0,
      )
  except NotAGNOSError:
    _run_dataflash_mock()
  except Exception as e:
    with df_lock:
      df_state.update(status="failed", message=str(e), ready=False, size=0)
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_dataflash_job() -> bool:
  # panda_lock is the gate: a running extract/dump/collect holds it, so a
  # concurrent dump is rejected here. The job thread releases it in its finally.
  if not panda_lock.acquire(blocking=False):
    return False
  with df_lock:
    df_state.update(status="running", frames=0, bytes=0, total=DUMP_TOTAL,
                    message="", ready=False, size=0)
  try:
    threading.Thread(target=_run_dataflash_job, name="tsk_dataflash_dump", daemon=True).start()
  except Exception:
    # The job thread never took ownership, so release the lock and clear the state
    # here — otherwise panda_lock would wedge every panda op until a restart.
    with df_lock:
      df_state.update(status="failed", message="Could not start the dump job.", ready=False)
    panda_lock.release()
    return False
  return True


def clear_dataflash() -> bool:
  # Refuse while a dump is in flight: a completing dump would otherwise re-set the
  # state and re-write the file this clear just removed. Returns False if running.
  with df_lock:
    if df_state["status"] == "running":
      return False
    df_state.update(ready=False, status="idle", frames=0, bytes=0,
                    total=DUMP_TOTAL, message="", size=0)
  for path in (dump_path(), Path(str(dump_path()) + ".partial")):
    try:
      path.unlink()
    except FileNotFoundError:
      pass
    except OSError:
      pass
  return True


def rehydrate_dataflash_state() -> None:
  # A completed dump persists on disk; reflect it after a restart so a finished
  # dump doesn't show as not-done and prompt a needless re-dump. A complete dump
  # is exactly DUMP_TOTAL bytes, so a truncated file can't masquerade as done.
  try:
    size = dump_path().stat().st_size
  except OSError:
    size = None
  if size == DUMP_TOTAL:
    with df_lock:
      df_state.update(ready=True, status="complete", frames=DUMP_TOTAL // 4,
                      bytes=DUMP_TOTAL, total=DUMP_TOTAL, size=DUMP_TOTAL,
                      message="Dump complete.")
    return
  # No complete dump, but a .partial sidecar means a near-complete run is on disk.
  # Reflect it as partial so Find stays enabled and the matcher falls back to it
  # after a restart (it finds the key in the captured range or asks for a re-dump).
  try:
    Path(str(dump_path()) + ".partial").stat()
  except OSError:
    return
  with df_lock:
    df_state.update(ready=False, status="partial", total=DUMP_TOTAL,
                    message="Partial dump on disk.\nTry the Find Toyota Security Key button.\n"
                            "If it doesn't work, restart the car into Not Ready To Drive mode and dump again.")


def _can_progress(seconds=None, sync=None, protected=None) -> None:
  with can_lock:
    if seconds is not None:
      can_state["seconds"] = seconds
    if sync is not None:
      can_state["sync_count"] = sync
    if protected is not None:
      can_state["protected_count"] = protected


def _run_can_mock() -> None:
  # Laptop dry run: ramp counts over a couple of seconds, then land on complete.
  for i in range(1, 7):
    time.sleep(0.4)
    _can_progress(seconds=i * 10.0, sync=i * 10, protected=i * 600)
  with can_lock:
    can_state.update(status="complete", ready=True, seconds=60.0,
                     sync_count=60, protected_count=3600,
                     message="Collected 60 sync and 3600 protected frames (mock).")


def _run_can_job() -> None:
  try:
    result = collect_can(progress_cb=_can_progress)
    status = result.get("status", "failed")
    with can_lock:
      can_state.update(
        status=status,
        sync_count=result.get("sync", can_state["sync_count"]),
        protected_count=result.get("protected", can_state["protected_count"]),
        message=result.get("message", ""),
        ready=(status == "complete"),
      )
  except NotAGNOSError:
    _run_can_mock()
  except Exception as e:
    with can_lock:
      can_state.update(status="failed", message=str(e), ready=False)
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_can_job() -> bool:
  # panda_lock is the gate: a running extract/dump/collect holds it, so a
  # concurrent collect is rejected here. The job thread releases it in its finally.
  if not panda_lock.acquire(blocking=False):
    return False
  with can_lock:
    can_state.update(status="running", sync_count=0, protected_count=0,
                     seconds=0.0, message="", ready=False)
  try:
    threading.Thread(target=_run_can_job, name="tsk_can_collect", daemon=True).start()
  except Exception:
    # Same as the dump: release the lock and clear the state if the thread that
    # would release it never starts.
    with can_lock:
      can_state.update(status="failed", message="Could not start the collection job.", ready=False)
    panda_lock.release()
    return False
  return True


def clear_can() -> bool:
  # Refuse while a collection is in flight so a finishing job can't resurrect the
  # oracle this clear just removed. Returns False if running.
  with can_lock:
    if can_state["status"] == "running":
      return False
    can_state.update(ready=False, status="idle", sync_count=0,
                     protected_count=0, seconds=0.0, message="")
  try:
    can_oracle_path().unlink()
  except FileNotFoundError:
    pass
  except OSError:
    pass
  return True


def rehydrate_can_state() -> None:
  # Reflect a persisted oracle as ready after a restart, mirroring the dump.
  sync, protected = count_oracle_frames()
  if sync >= SYNC_TARGET and protected >= PROTECTED_TARGET:
    with can_lock:
      can_state.update(ready=True, status="complete", sync_count=sync,
                       protected_count=protected,
                       message=f"Collected {sync} sync and {protected} protected frames.")


def _sniff_progress(seconds=None, frames=None, buses=None) -> None:
  with sniff_lock:
    if seconds is not None:
      sniff_state["seconds"] = seconds
    if frames is not None:
      sniff_state["frames"] = frames
    if buses is not None:
      sniff_state["bus_count"] = buses


def _run_sniff_mock() -> None:
  # Laptop dry run: ramp progress, then land on a plausible bus map (bus 0 carrying
  # the SecOC markers, bus 1 with unrelated traffic, bus 2 silent) so the page
  # layout is exercised. summarize_counts keeps the shape identical to the real run.
  from collections import Counter
  for i in range(1, 5):
    time.sleep(0.4)
    _sniff_progress(seconds=i * 2.0, frames=i * 260, buses=2)
  demo = {
    0: Counter({0x0f: 30, 0x2e4: 50, 0x131: 40, 0x344: 20, 0x25: 120, 0xaa: 120}),
    1: Counter({0x3bc: 12, 0x1c4: 12}),
  }
  demo_maxlen = {0: 8, 1: 64}   # bus 1 carrying CAN-FD frames, to exercise the FD display
  result = summarize_counts(demo, 8.0, demo_maxlen)
  with sniff_lock:
    sniff_state.update(status="complete", seconds=result["seconds"], frames=result["total"],
                       total=result["total"], buses=result["buses"], markers=result["markers"],
                       fd_buses=result["fd_buses"], message=result["message"] + " (mock)")


def _run_sniff_job() -> None:
  try:
    result = sniff_can(progress_cb=_sniff_progress)
    with sniff_lock:
      sniff_state.update(
        status=result.get("status", "failed"),
        seconds=result.get("seconds", 0.0),
        frames=result.get("total", 0),
        total=result.get("total", 0),
        buses=result.get("buses", []),
        markers=result.get("markers", []),
        fd_buses=result.get("fd_buses", []),
        message=result.get("message", ""),
      )
  except NotAGNOSError:
    _run_sniff_mock()
  except Exception as e:
    with sniff_lock:
      sniff_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_sniff_job() -> bool:
  # panda_lock is the gate: a running extract/dump/collect holds it, so a
  # concurrent sniff is rejected here. The job thread releases it in its finally.
  if not panda_lock.acquire(blocking=False):
    return False
  with sniff_lock:
    sniff_state.update(status="running", seconds=0.0, frames=0, bus_count=0,
                       total=0, buses=[], markers=[], message="")
  try:
    threading.Thread(target=_run_sniff_job, name="tsk_can_sniff", daemon=True).start()
  except Exception:
    # Same as the other jobs: release the lock and clear state if the thread that
    # would release it never starts.
    with sniff_lock:
      sniff_state.update(status="failed", message="Could not start the sniff job.")
    panda_lock.release()
    return False
  return True


def _diag_progress(steps=None, last=None) -> None:
  with diag_lock:
    if steps is not None:
      diag_state["step_count"] = steps
    if last is not None:
      diag_state["last"] = last


def _run_diag_mock() -> None:
  # Laptop dry run: a realistic out-of-family result — identity reads return, the
  # session flow passes, and the EPS rejects the Willem key at security access.
  for i, name in enumerate(("connect panda", "session EXTENDED", "identity", "security SEND_KEY"), 1):
    time.sleep(0.3)
    _diag_progress(steps=i, last=name)
  with diag_lock:
    diag_state.update(
      status="rejected",
      step_count=7,
      last="security SEND_KEY",
      panda="1.7.0-mock",
      eps_bus=0,
      identity=[
        {"did": "0xf181", "name": "app_sw_id", "hex": "018965b0000000", "ascii": ".8965B......"},
        {"did": "0xf187", "name": "spare_part_no", "hex": "3839363542", "ascii": "8965B"},
        {"did": "0xf18c", "name": "ecu_serial", "hex": "", "ascii": "NRC 0x31 request out of range"},
      ],
      steps=[
        {"name": "connect panda", "ok": True, "detail": "fw 1.7.0-mock", "ms": 42},
        {"name": "probe bus 0 (default session)", "ok": True, "detail": "EPS responded", "ms": 12},
        {"name": "session EXTENDED", "ok": True, "detail": "ok", "ms": 9},
        {"name": "session PROGRAMMING", "ok": True, "detail": "ok", "ms": 11},
        {"name": "session PROGRAMMING (repeat)", "ok": True, "detail": "ok", "ms": 8},
        {"name": "security REQUEST_SEED", "ok": True, "detail": "0011223344556677", "ms": 15},
        {"name": "security SEND_KEY", "ok": False, "detail": "NRC 0x35 invalid key", "ms": 14},
      ],
      failed_at="security SEND_KEY",
      exception="NegativeResponseError: securityAccess - invalid key",
      traceback="(mock traceback)",
      frames=0, bytes=0,
      message="EPS rejected the Willem key at security access — not in the exploit family (mock).",
    )


def _run_diag_job() -> None:
  try:
    result = dump_diagnose(progress_cb=_diag_progress)
    with diag_lock:
      diag_state.update(
        status=result.get("status", "failed"),
        panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1),
        identity=result.get("identity", []),
        steps=result.get("steps", []),
        step_count=len(result.get("steps", [])),
        failed_at=result.get("failed_at", ""),
        exception=result.get("exception", ""),
        traceback=result.get("traceback", ""),
        frames=result.get("frames", 0),
        bytes=result.get("bytes", 0),
        message=result.get("message", ""),
      )
  except NotAGNOSError:
    _run_diag_mock()
  except Exception as e:
    with diag_lock:
      diag_state.update(status="failed", message=str(e), traceback=traceback.format_exc())
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_diag_job() -> bool:
  # panda_lock gates it against extract/dump/collect/sniff, released in the finally.
  if not panda_lock.acquire(blocking=False):
    return False
  with diag_lock:
    diag_state.update(status="running", step_count=0, last="", panda="", eps_bus=-1,
                      identity=[], steps=[], failed_at="", exception="", traceback="",
                      frames=0, bytes=0, message="")
  try:
    threading.Thread(target=_run_diag_job, name="tsk_dataflash_diag", daemon=True).start()
  except Exception:
    with diag_lock:
      diag_state.update(status="failed", message="Could not start the diagnostic job.")
    panda_lock.release()
    return False
  return True


def _probe_progress(attempts=None, last=None) -> None:
  with probe_lock:
    if attempts is not None:
      probe_state["attempt_count"] = attempts
    if last is not None:
      probe_state["last"] = last


def _run_probe_mock() -> None:
  # Laptop dry run: EPS on bus 1, every entry sequence times out, and the security
  # attempt returns a seed but rejects the Willem key — the expected out-of-family shape.
  names = ("extended -> programming (3s)", "double programming (1s settle)",
           "default -> programming direct", "tester-present -> programming",
           "security-first -> programming")
  for i, name in enumerate(names, 1):
    time.sleep(0.3)
    _probe_progress(attempts=i, last=name)
  timeout = "MessageTimeoutError: timeout waiting for response"
  with probe_lock:
    probe_state.update(
      status="blocked",
      attempt_count=8,
      last="all-bus-listen",
      panda="1.7.0-mock",
      eps_bus=1,
      attempts=[
        {"name": names[0], "ok": False, "detail": timeout, "programming": True},
        {"name": names[1], "ok": False, "detail": timeout, "programming": True},
        {"name": names[2], "ok": False, "detail": timeout, "programming": True},
        {"name": names[3], "ok": False, "detail": timeout, "programming": True},
        {"name": "safety-system session (0x04)", "ok": False, "detail": timeout, "programming": False},
        {"name": names[4], "ok": False, "detail": "send_key NRC 0x35 invalid key", "programming": True},
      ],
      security={"seed": "0011223344556677", "send_key": "NRC 0x35 invalid key", "programming": ""},
      security_levels=[
        {"level": "0x01", "detail": "NRC 0x7e subFunctionNotSupportedInActiveSession"},
        {"level": "0x03", "detail": "NRC 0x7e subFunctionNotSupportedInActiveSession"},
        {"level": "0x05", "detail": "NRC 0x31 requestOutOfRange"},
        {"level": "0x07", "detail": "NRC 0x31 requestOutOfRange"},
        {"level": "0x09", "detail": "NRC 0x31 requestOutOfRange"},
        {"level": "0x0b", "detail": "NRC 0x31 requestOutOfRange"},
      ],
      did_it_take={"before": "0x03", "after": "NRC 0x31 requestOutOfRange", "switched": None},
      all_bus=[
        {"bus": 0, "unique": 22, "saw_eps_response": False, "ids": ["0x25", "0xaa", "0xb4"]},
        {"bus": 1, "unique": 3, "saw_eps_response": False, "ids": ["0x1c4", "0x3bc"]},
        {"bus": 2, "unique": 22, "saw_eps_response": False, "ids": ["0x25", "0xaa", "0xb4"]},
      ],
      message="No sequence entered on bus 1; the session DID was unreadable so did-it-take is "
              "inconclusive. Use all-bus-listen (a reroute) as the deciding signal. (mock)",
    )


def _run_probe_job() -> None:
  try:
    result = probe_programming(progress_cb=_probe_progress)
    with probe_lock:
      probe_state.update(
        status=result.get("status", "failed"),
        panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1),
        attempts=result.get("attempts", []),
        attempt_count=len(result.get("attempts", [])),
        security=result.get("security", {}),
        security_levels=result.get("security_levels", []),
        did_it_take=result.get("did_it_take", {}),
        all_bus=result.get("all_bus", []),
        message=result.get("message", ""),
      )
  except NotAGNOSError:
    _run_probe_mock()
  except Exception as e:
    with probe_lock:
      probe_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_probe_job() -> bool:
  # panda_lock gates it against extract/dump/collect/sniff/diag, released in the finally.
  if not panda_lock.acquire(blocking=False):
    return False
  with probe_lock:
    probe_state.update(status="running", attempt_count=0, last="", panda="", eps_bus=-1,
                       attempts=[], security={}, message="")
  try:
    threading.Thread(target=_run_probe_job, name="tsk_prog_probe", daemon=True).start()
  except Exception:
    with probe_lock:
      probe_state.update(status="failed", message="Could not start the probe job.")
    panda_lock.release()
    return False
  return True


def _readmem_progress(reads=None, last=None) -> None:
  with readmem_lock:
    if reads is not None:
      readmem_state["count"] = reads
    if last is not None:
      readmem_state["last"] = last


def _run_readmem_mock() -> None:
  # Laptop dry run: the expected Corolla shape — 0x23 refused at every address.
  for i, name in enumerate(("key region (extended)", "dataflash base (extended)",
                            "ram (control) (extended)", "key region (default)"), 1):
    time.sleep(0.3)
    _readmem_progress(reads=i, last=name)
  with readmem_lock:
    readmem_state.update(
      status="denied", count=4, last="key region (default)", panda="1.7.0-mock", eps_bus=1,
      reads=[
        {"name": "key region", "session": "extended", "address": "0xff206e14", "size": 16,
         "ok": False, "detail": "NRC 0x33 securityAccessDenied"},
        {"name": "dataflash base", "session": "extended", "address": "0xff200000", "size": 16,
         "ok": False, "detail": "NRC 0x33 securityAccessDenied"},
        {"name": "ram (control)", "session": "extended", "address": "0xfebf0000", "size": 16,
         "ok": False, "detail": "NRC 0x31 requestOutOfRange"},
        {"name": "key region", "session": "default", "address": "0xff206e14", "size": 16,
         "ok": False, "detail": "NRC 0x7f serviceNotSupportedInActiveSession"},
      ],
      message="0x23 was refused at every address — direct memory reads are not allowed here. (mock)",
    )


def _run_readmem_job() -> None:
  try:
    result = read_key_region(progress_cb=_readmem_progress)
    with readmem_lock:
      readmem_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), reads=result.get("reads", []),
        count=len(result.get("reads", [])), message=result.get("message", ""),
      )
  except NotAGNOSError:
    _run_readmem_mock()
  except Exception as e:
    with readmem_lock:
      readmem_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_readmem_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with readmem_lock:
    readmem_state.update(status="running", count=0, last="", panda="", eps_bus=-1, reads=[], message="")
  try:
    threading.Thread(target=_run_readmem_job, name="tsk_read_mem", daemon=True).start()
  except Exception:
    with readmem_lock:
      readmem_state.update(status="failed", message="Could not start the read-memory job.")
    panda_lock.release()
    return False
  return True


def _ident_progress(items=None, last=None) -> None:
  with ident_lock:
    if items is not None:
      ident_state["count"] = items
    if last is not None:
      ident_state["last"] = last


def _run_ident_mock() -> None:
  for i in range(1, 6):
    time.sleep(0.25)
    _ident_progress(items=i * 4, last=f"item {i * 4}")
  with ident_lock:
    ident_state.update(
      status="mapped", count=24, last="0x19 read DTC info", panda="1.7.0-mock", eps_bus=1,
      identity=[
        {"did": "0xf181", "name": "app_sw_id", "hex": "383936354631323038303030", "ascii": "8965F1208000"},
        {"did": "0xf186", "name": "active_session", "hex": "03", "ascii": "."},
        {"did": "0xf187", "name": "spare_part_no", "hex": "", "ascii": "NRC 0x31 requestOutOfRange"},
        {"did": "0xf18c", "name": "ecu_serial", "hex": "38393635303132", "ascii": "8965012"},
        {"did": "0xf190", "name": "vin", "hex": "", "ascii": "NRC 0x31 requestOutOfRange"},
      ],
      services=[
        {"name": "0x10 session control", "supported": True, "detail": "supported"},
        {"name": "0x22 read data by id", "supported": True, "detail": "supported"},
        {"name": "0x23 read memory", "supported": True, "detail": "supported (NRC 0x33 securityAccessDenied)"},
        {"name": "0x27 security access", "supported": True, "detail": "supported (NRC 0x7e subFunctionNotSupportedInActiveSession)"},
        {"name": "0x3e tester present", "supported": True, "detail": "supported"},
        {"name": "0x19 read DTC info", "supported": True, "detail": "supported"},
      ],
      message="Read 3 identity field(s); 6 of 6 probed services answered. (mock)",
    )


def _run_ident_job() -> None:
  try:
    result = map_surface(progress_cb=_ident_progress)
    with ident_lock:
      ident_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), identity=result.get("identity", []),
        services=result.get("services", []),
        count=len(result.get("identity", [])) + len(result.get("services", [])),
        message=result.get("message", ""),
      )
  except NotAGNOSError:
    _run_ident_mock()
  except Exception as e:
    with ident_lock:
      ident_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_ident_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with ident_lock:
    ident_state.update(status="running", count=0, last="", panda="", eps_bus=-1,
                       identity=[], services=[], message="")
  try:
    threading.Thread(target=_run_ident_job, name="tsk_ident_map", daemon=True).start()
  except Exception:
    with ident_lock:
      ident_state.update(status="failed", message="Could not start the identity-map job.")
    panda_lock.release()
    return False
  return True


def _reset_progress(attempts=None, last=None) -> None:
  with reset_lock:
    if attempts is not None:
      reset_state["count"] = attempts
    if last is not None:
      reset_state["last"] = last


def _run_reset_mock() -> None:
  for i in range(1, 5):
    time.sleep(0.3)
    _reset_progress(attempts=i, last=f"{i * 900}ms timeout")
  with reset_lock:
    reset_state.update(
      status="blocked", count=4, last="2700ms timeout", panda="1.7.0-mock", eps_bus=1,
      reset="hard reset accepted",
      attempts=[
        {"t_ms": 5, "detail": "timeout"},
        {"t_ms": 900, "detail": "timeout"},
        {"t_ms": 1800, "detail": "timeout"},
        {"t_ms": 2700, "detail": "timeout"},
      ],
      session_after="NRC 0x31 requestOutOfRange",
      message="No PROGRAMMING acceptance in the reset window. Active session after reset: "
              "NRC 0x31 requestOutOfRange (0x02 would mean it switched silently). (mock)",
    )


def _run_reset_job() -> None:
  try:
    result = probe_reset_window(progress_cb=_reset_progress)
    with reset_lock:
      reset_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), reset=result.get("reset", ""),
        attempts=result.get("attempts", []), count=len(result.get("attempts", [])),
        session_after=result.get("session_after", ""), message=result.get("message", ""),
      )
  except NotAGNOSError:
    _run_reset_mock()
  except Exception as e:
    with reset_lock:
      reset_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_reset_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with reset_lock:
    reset_state.update(status="running", count=0, last="", panda="", eps_bus=-1,
                       reset="", attempts=[], session_after="", message="")
  try:
    threading.Thread(target=_run_reset_job, name="tsk_reset_probe", daemon=True).start()
  except Exception:
    with reset_lock:
      reset_state.update(status="failed", message="Could not start the reset-probe job.")
    panda_lock.release()
    return False
  return True


def _level3_progress(tests=None, last=None) -> None:
  with level3_lock:
    if tests is not None:
      level3_state["count"] = tests
    if last is not None:
      level3_state["last"] = last


def _run_level3_mock() -> None:
  # Laptop dry run: the reproduced shape — 0x03 answers from a clean extended session.
  for i, name in enumerate(("clean extended (0x03 first)", "default session (no extended)",
                            "0x01 first, then 0x03", "programming poke, then 0x03"), 1):
    time.sleep(0.3)
    _level3_progress(tests=i, last=name)
  with level3_lock:
    level3_state.update(
      status="reproduced", count=4, last="programming poke, then 0x03", panda="1.7.0-mock", eps_bus=1,
      seeds=["da2df2eff64d95f5426bf3af70bb49aa", "1c9a4f0b77e3d5218a6c4b0fe29d3a11",
             "77aa10c4be5518e2049f3c6d1b8e720d", "9be1035fac82d4761e0b5528cf94a6d3"],
      primer="",
      tests=[
        {"name": "clean extended (0x03 first)", "got_seed": True,
         "seed": "da2df2eff64d95f5426bf3af70bb49aa",
         "steps": [
           {"step": "default", "detail": "accepted"},
           {"step": "extended", "detail": "accepted"},
           {"step": "seed 0x03", "detail": "seed da2df2eff64d95f5426bf3af70bb49aa"},
           {"step": "seed 0x03 again", "detail": "seed 1c9a4f0b77e3d5218a6c4b0fe29d3a11"},
         ]},
        {"name": "default session (no extended)", "got_seed": False, "seed": "",
         "steps": [
           {"step": "default", "detail": "accepted"},
           {"step": "seed 0x03", "detail": "NRC 0x7e subFunctionNotSupportedInActiveSession"},
         ]},
        {"name": "0x01 first, then 0x03", "got_seed": True,
         "seed": "77aa10c4be5518e2049f3c6d1b8e720d",
         "steps": [
           {"step": "default", "detail": "accepted"},
           {"step": "extended", "detail": "accepted"},
           {"step": "seed 0x01", "detail": "NRC 0x7e subFunctionNotSupportedInActiveSession"},
           {"step": "seed 0x03", "detail": "seed 77aa10c4be5518e2049f3c6d1b8e720d"},
         ]},
        {"name": "programming poke, then 0x03", "got_seed": True,
         "seed": "9be1035fac82d4761e0b5528cf94a6d3",
         "steps": [
           {"step": "default", "detail": "accepted"},
           {"step": "extended", "detail": "accepted"},
           {"step": "poke programming", "detail": "sent 10 02 (ignored response)"},
           {"step": "seed 0x03", "detail": "seed 9be1035fac82d4761e0b5528cf94a6d3"},
         ]},
      ],
      message="Level 0x03 returned a seed from a clean extended session on bus 1 (seeds differ each "
              "request) — it is its own input/output, not a side effect of prior traffic. (mock)",
    )


def _run_level3_job() -> None:
  try:
    result = probe_level3(progress_cb=_level3_progress)
    with level3_lock:
      level3_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), tests=result.get("tests", []),
        seeds=result.get("seeds", []), primer=result.get("primer", ""),
        count=len(result.get("tests", [])), message=result.get("message", ""),
      )
  except NotAGNOSError:
    _run_level3_mock()
  except Exception as e:
    with level3_lock:
      level3_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_level3_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with level3_lock:
    level3_state.update(status="running", count=0, last="", panda="", eps_bus=-1,
                        tests=[], seeds=[], primer="", message="")
  try:
    threading.Thread(target=_run_level3_job, name="tsk_level3_probe", daemon=True).start()
  except Exception:
    with level3_lock:
      level3_state.update(status="failed", message="Could not start the level-0x03 probe.")
    panda_lock.release()
    return False
  return True


def _sendkey_progress(step=None, last=None) -> None:
  with sendkey_lock:
    if last is not None:
      sendkey_state["last"] = last


def _run_sendkey_mock() -> None:
  # Laptop dry run: the realistic shape — the Sienna secret is rejected on the Corolla.
  for step in ("extended", "seed", "key", "send_key"):
    time.sleep(0.25)
    _sendkey_progress(step=step, last=step)
  with sendkey_lock:
    sendkey_state.update(
      status="invalid_key", last="send_key", panda="1.7.0-mock", eps_bus=1, session="extended",
      seed="da2df2eff64d95f5426bf3af70bb49aa",
      key="3f9c1a04d8b27e6510c23a9fbe4d7182",
      send_key="NRC 0x35 invalidKey",
      post_unlock_reads=[],
      message="Willem key rejected (invalid key) — the Corolla uses a different seed->key secret. "
              "The firmware-dump path is needed to recover it. (mock)",
    )


def _run_sendkey_job() -> None:
  try:
    result = send_willem_key(progress_cb=_sendkey_progress)
    with sendkey_lock:
      sendkey_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), session=result.get("session", ""),
        seed=result.get("seed", ""), key=result.get("key", ""),
        send_key=result.get("send_key", ""),
        post_unlock_reads=result.get("post_unlock_reads", []),
        message=result.get("message", ""),
      )
  except NotAGNOSError:
    _run_sendkey_mock()
  except Exception as e:
    with sendkey_lock:
      sendkey_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_sendkey_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with sendkey_lock:
    sendkey_state.update(status="running", last="", panda="", eps_bus=-1, session="",
                         seed="", key="", send_key="", post_unlock_reads=[], message="")
  try:
    threading.Thread(target=_run_sendkey_job, name="tsk_sendkey_probe", daemon=True).start()
  except Exception:
    with sendkey_lock:
      sendkey_state.update(status="failed", message="Could not start the send-key probe.")
    panda_lock.release()
    return False
  return True


def _preamble_progress(steps=None, last=None) -> None:
  with preamble_lock:
    if steps is not None:
      preamble_state["count"] = steps
    if last is not None:
      preamble_state["last"] = last


def _run_preamble_mock() -> None:
  # Laptop dry run: the expected in-car shape — no lock, programming still refused, and
  # the DTC diff empty (the reading that points at a lower-layer drop).
  for i, name in enumerate(("lock read", "0x01 baseline", "exploit surface",
                            "0x85 -> programming", "0x85 + 0x28 -> programming",
                            "0x85 + 0x28 -> programming (6s)",
                            "0x85 + 0x28 -> 10 82 suppressed",
                            "functional 0x28 -> programming", "DTC diff"), 1):
    time.sleep(0.25)
    _preamble_progress(steps=i, last=name)

  def variant(name, prog):
    return {
      "name": name, "opened": False, "programming": prog, "session_after": "0x03",
      "seed_01_after": "NRC 0x7e subFunctionNotSupportedInActiveSession",
      "steps": [
        {"step": "extended", "detail": "accepted"},
        {"step": "0x85 DTC off", "detail": "accepted"},
        {"step": "0x28 disable tx", "detail": "accepted"},
      ],
    }

  with preamble_lock:
    preamble_state.update(
      status="blocked", count=9, last="DTC diff", panda="1.7.0-mock", eps_bus=1,
      identity=[
        {"name": "app_sw_id", "ok": True, "detail": "8965F1208000 (383936354631323038303030)"},
        {"name": "ecu_serial", "ok": True, "detail": "8965012N50E12H030731 (38393635…)"},
        {"name": "active_session", "ok": True, "detail": "0x03"},
      ],
      lock={
        "extended": "accepted",
        "seed_03": "seed 5b1e9c77aa304f628d1b0e5942cf7a83",
        "seed_01_baseline": "NRC 0x7e subFunctionNotSupportedInActiveSession",
        "locked": False,
      },
      services=[
        {"name": "extended", "ok": True, "detail": "accepted"},
        {"name": "read DID 0x201 (did_201_key)", "ok": False,
         "detail": "NRC 0x31 requestOutOfRange"},
        {"name": "read DID 0x202 (did_202_iv)", "ok": False,
         "detail": "NRC 0x31 requestOutOfRange"},
        {"name": "read DID 0x203 (did_203_state)", "ok": False,
         "detail": "NRC 0x31 requestOutOfRange"},
        {"name": "routine results 0x10f0", "ok": False,
         "detail": "NRC 0x7f serviceNotSupportedInActiveSession"},
        {"name": "request download (RAM)", "ok": False,
         "detail": "NRC 0x7f serviceNotSupportedInActiveSession"},
        {"name": "0x85 DTC setting OFF", "ok": True, "detail": "accepted"},
        {"name": "0x28 comm control disable-tx", "ok": True, "detail": "accepted"},
        {"name": "DTC snapshot (before)", "ok": True, "detail": "3 codes"},
      ],
      variants=[
        variant("0x85 -> programming", "MessageTimeoutError"),
        variant("0x85 + 0x28 -> programming", "MessageTimeoutError"),
        variant("0x85 + 0x28 -> programming (6s)", "MessageTimeoutError"),
        variant("0x85 + 0x28 -> 10 82 suppressed", "sent (suppressed) — see session read"),
        variant("functional 0x28 -> programming", "MessageTimeoutError"),
      ],
      dtc={"before": ["c11234:08", "c15678:2f", "c1aa01:08"],
           "after": ["c11234:08", "c15678:2f", "c1aa01:08"], "new": []},
      reads=[
        {"name": "key region 0xff206e14", "ok": False, "detail": "NRC 0x31 requestOutOfRange"},
        {"name": "dataflash base 0xff200000", "ok": False, "detail": "NRC 0x31 requestOutOfRange"},
        {"name": "ram window 0xfebf0000", "ok": False, "detail": "NRC 0x31 requestOutOfRange"},
      ],
      liveness="EPS still answering at end of run",
      message="Programming still refused with the pre-programming preamble (0 new DTC(s)). "
              "Level 0x01 stayed shut. Screenshot and send to Calvin — the DTC diff and the "
              "service refusal codes are the useful part of this run even though programming "
              "did not open. (mock)",
    )


def _run_preamble_job() -> None:
  try:
    result = probe_preamble(progress_cb=_preamble_progress)
    with preamble_lock:
      preamble_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), identity=result.get("identity", []),
        lock=result.get("lock", {}), services=result.get("services", []),
        variants=result.get("variants", []), dtc=result.get("dtc", {}),
        reads=result.get("reads", []), liveness=result.get("liveness", ""),
        message=result.get("message", ""),
      )
  except NotAGNOSError:
    _run_preamble_mock()
  except Exception as e:
    with preamble_lock:
      preamble_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_preamble_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with preamble_lock:
    preamble_state.update(status="running", count=0, last="", panda="", eps_bus=-1,
                          identity=[], lock={}, services=[], variants=[], dtc={},
                          reads=[], liveness="", message="")
  try:
    threading.Thread(target=_run_preamble_job, name="tsk_preamble_probe", daemon=True).start()
  except Exception:
    with preamble_lock:
      preamble_state.update(status="failed", message="Could not start the preamble probe.")
    panda_lock.release()
    return False
  return True


def _sweep_progress(steps=None, last=None, stage=None) -> None:
  with sweep_lock:
    if steps is not None:
      sweep_state["count"] = steps
    if last is not None:
      sweep_state["last"] = last
    if stage is not None:
      sweep_state["stage"] = stage


def _run_sweep_mock() -> None:
  # Laptop dry run: the partial shape — the budget runs out mid sub-function sweep, which
  # is the expected first-session outcome in the car.
  for i, (stage, last) in enumerate((
      ("calibrate", "calibrated"), ("services", "services default"),
      ("services", "services extended"), ("subfunctions", "sub-functions of 0x10"),
      ("subfunctions", "sub-functions of 0x22"), ("dids", "DIDs identity"),
      ("addresses", "address sweep"), ("cross", "cross-ECU silent set")), 1):
    time.sleep(0.25)
    _sweep_progress(steps=i * 64, last=last, stage=stage)
  with sweep_lock:
    sweep_state.update(
      status="partial", count=812, last="sub-functions of 0x27", stage="subfunctions",
      panda="1.7.0-mock", eps_bus=1, timeout_ms=120, records=812,
      stages=[
        {"name": "calibrate", "detail": "round trip 12 ms → timeout 120 ms"},
        {"name": "services/default", "detail": "256 sent"},
        {"name": "services/extended", "detail": "256 sent"},
        {"name": "subfunctions/10", "detail": "256 sent"},
        {"name": "dids/identity", "detail": "44 sent"},
        {"name": "addresses", "detail": "3 responder(s)"},
      ],
      answering=["0x10", "0x14", "0x19", "0x22", "0x23", "0x27", "0x2e", "0x31", "0x3e"],
      silent=["0x28", "0x34", "0x36", "0x37", "0x85"],
      responders=["0x7a1", "0x7b0", "0x7e0"],
      frontier="subfunctions: stopped at 0x27 sub 0x40",
      message="Budget reached — 812 results saved. subfunctions: stopped at 0x27 sub 0x40. "
              "Run this page again (Not Ready to Drive) and it resumes where it stopped. "
              "Screenshot and send to Calvin. (mock)",
    )


def _run_sweep_job() -> None:
  try:
    result = sweep(progress_cb=_sweep_progress)
    with sweep_lock:
      sweep_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), timeout_ms=result.get("timeout_ms", 0),
        stages=result.get("stages", []), answering=result.get("answering", []),
        silent=result.get("silent", []), responders=result.get("responders", []),
        records=result.get("records", 0), frontier=result.get("frontier", ""),
        message=result.get("message", ""),
      )
  except NotAGNOSError:
    _run_sweep_mock()
  except Exception as e:
    with sweep_lock:
      sweep_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_sweep_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with sweep_lock:
    sweep_state.update(status="running", count=0, last="", stage="", panda="", eps_bus=-1,
                       timeout_ms=0, stages=[], answering=[], silent=[], responders=[],
                       records=0, frontier="", message="")
  try:
    threading.Thread(target=_run_sweep_job, name="tsk_uds_sweep", daemon=True).start()
  except Exception:
    with sweep_lock:
      sweep_state.update(status="failed", message="Could not start the UDS sweep.")
    panda_lock.release()
    return False
  return True


def _ready_progress(steps=None, last=None, stage=None) -> None:
  with ready_lock:
    if steps is not None:
      ready_state["count"] = steps
    if last is not None:
      ready_state["last"] = last
    if stage is not None:
      ready_state["stage"] = stage


def _run_ready_mock() -> None:
  for i, (stage, last) in enumerate((
      ("capture", "capturing 30s / 90s"), ("capture", "capturing 90s / 90s"),
      ("capture", "capture analysed"), ("diff", "reflash set: programming session"),
      ("addresses", "address sweep")), 1):
    time.sleep(0.3)
    _ready_progress(steps=i * 900, last=last, stage=stage)
  with ready_lock:
    ready_state.update(
      status="captured", count=4500, last="address sweep", stage="addresses",
      panda="1.7.0-mock", eps_bus=1, frames=41208,
      capture={
        "ids": 147, "frames": 41208,
        "candidates": [
          {"bus": 1, "addr": "0x1c4", "samples": 1780, "tail_distinct": 0.998, "head_distinct": 0.061},
          {"bus": 1, "addr": "0x260", "samples": 1774, "tail_distinct": 0.996, "head_distinct": 0.044},
          {"bus": 1, "addr": "0x2a1", "samples": 890, "tail_distinct": 0.991, "head_distinct": 0.112},
        ],
        "sync": [{"bus": 1, "addr": "0x00f", "samples": 88, "distinct": 88}],
      },
      diff=[
        {"label": "reflash set: programming session", "request": "1002", "outcome": "silent", "nrc": -1, "raw": ""},
        {"label": "reflash set: communication control", "request": "28", "outcome": "silent", "nrc": -1, "raw": ""},
        {"label": "reflash set: request download", "request": "34", "outcome": "silent", "nrc": -1, "raw": ""},
        {"label": "reflash set: control DTC setting", "request": "85", "outcome": "silent", "nrc": -1, "raw": ""},
      ],
      responders=["0x7a1", "0x7b0", "0x7c0", "0x7e0"],
      cross=[
        {"addr": "0x7b0", "label": "control DTC setting", "outcome": "nrc", "nrc": 0x7f},
        {"addr": "0x7e0", "label": "control DTC setting", "outcome": "positive", "nrc": -1},
      ],
      seeds=[
        {"level": "0x01", "outcome": "nrc", "nrc": 0x7e, "raw": "7f277e"},
        {"level": "0x03", "outcome": "positive", "nrc": -1, "raw": "2703aabbccdd"},
      ],
      message="Captured 41208 frames across 147 IDs; 3 look SecOC-signed. Mode diff: 0 of 4 "
              "answered in READY that did not in Not Ready to Drive. 4 responder(s) on the "
              "bus. Screenshot and send to Calvin — the capture file is saved on the device "
              "for offline analysis. (mock)",
    )


def _run_ready_job() -> None:
  try:
    result = capture_ready(progress_cb=_ready_progress)
    with ready_lock:
      ready_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), capture=result.get("capture", {}),
        diff=result.get("diff", []), responders=result.get("responders", []),
        cross=result.get("cross", []), seeds=result.get("seeds", []),
        frames=result.get("frames", 0), message=result.get("message", ""),
      )
  except NotAGNOSError:
    _run_ready_mock()
  except Exception as e:
    with ready_lock:
      ready_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_ready_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with ready_lock:
    ready_state.update(status="running", count=0, last="", stage="", panda="", eps_bus=-1,
                       capture={}, diff=[], responders=[], cross=[], seeds=[], frames=0,
                       message="")
  try:
    threading.Thread(target=_run_ready_job, name="tsk_ready_capture", daemon=True).start()
  except Exception:
    with ready_lock:
      ready_state.update(status="failed", message="Could not start the READY capture.")
    panda_lock.release()
    return False
  return True


class TSKWebHandler(BaseHTTPRequestHandler):
  server_version = "TSKWeb/0.1"

  def _send_extract_dry_run(self) -> None:
    global dry_run_counter
    scenario = dry_run_counter % 3
    dry_run_counter += 1

    if scenario == 0:
      KeyFileManager().install_key(DRY_RUN_FAKE_KEY)
      self._send_json({
        "ok": True,
        "key": DRY_RUN_FAKE_KEY,
        "message": f"Success!\n\nThis is your key:\n{format_key(DRY_RUN_FAKE_KEY)}\n\nTake a screenshot now.",
      })
    elif scenario == 1:
      self._send_json({
        "ok": False,
        "message": "pandad is not running.\n\nTry again. If the problem persists, turn off the car, "
                   "put it back into 'Not Ready to Drive' mode, and then try again."
                   f"\n\n{PING_REPORT}",
      }, status=HTTPStatus.CONFLICT)
    else:
      self._send_json({
        "ok": False,
        "message": (
          "UDS request timed out\n\n"
          "Traceback (most recent call last):\n"
          '  File "/data/openpilot/tsk/lib/extractor.py", line 384, in run\n'
          "    secoc_key = cls.hack()\n"
          '  File "/data/openpilot/tsk/lib/extractor.py", line 241, in hack\n'
          "    seed = cls._security_access(panda)\n"
          '  File "/data/openpilot/tsk/lib/extractor.py", line 152, in _security_access\n'
          "    resp = cls._uds_request(panda, service=0x27, subfunction=0x01)\n"
          '  File "/data/openpilot/tsk/lib/extractor.py", line 113, in _uds_request\n'
          "    raise RetryError(f\"UDS request timed out\")\n"
          "tsk.lib.extractor.RetryError: UDS request timed out\n\n"
          "!!!! Unexpected error. Please take a screenshot, post it on #toyota-security, and ping @calvinspark\n"
        ),
      }, status=HTTPStatus.INTERNAL_SERVER_ERROR)

  def do_GET(self) -> None:
    self._handle_request(send_body=True)

  def do_HEAD(self) -> None:
    self._handle_request(send_body=False)

  def do_POST(self) -> None:
    path = urlparse(self.path).path

    if path == "/api/extract":
      if not panda_lock.acquire(blocking=False):
        self._send_json({
          "ok": False,
          "message": "Another panda operation (dump or CAN collect) is in progress.",
        }, status=HTTPStatus.CONFLICT)
        return

      try:
        secoc_key = TSKExtractor.hack()
        KeyFileManager().install_key(secoc_key)
        self._send_json({
          "ok": True,
          "key": secoc_key,
          "message": f"Success!\n\nThis is your key:\n{format_key(secoc_key)}\n\nTake a screenshot now.",
        })
      except NotAGNOSError:
        self._send_extract_dry_run()
        return
      except Exception as e:
        tb = traceback.format_exc()
        self._send_json({
          "ok": False,
          "message": f"{e}\n\n{tb}\n\n{PING_REPORT}",
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      finally:
        TSKExtractor._close_panda()
        panda_lock.release()
      return

    if path == "/api/match":
      if not matcher_lock.acquire(blocking=False):
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "Key finder is already running.",
        }, status=HTTPStatus.CONFLICT)
        return

      try:
        result = run_matcher()
        if result["status"] == "found":
          KeyFileManager().install_key(result["key"])
          # Same body for a complete or a partial recovery — the title carries
          # "Success!", so the body opens straight at the key.
          detail = (
            f"Found at {result['address']} — {result['matches']} matches "
            f"(sync {result['sync']}, protected {result['protected']})."
          )
          message = (
            f"This is your key:\n{format_key(result['key'])}\n\n"
            f"{detail}\n\n"
            "Take a screenshot now."
          )
          self._send_json({
            "ok": True,
            "status": "found",
            "key": result["key"],
            "message": message,
            **RebootManager.key_status_payload(),
          })
        else:
          # Forward the matcher's debug fields; index.html builds the not-found
          # debug block from these plus the dump/oracle counts it already polls.
          self._send_json({
            "ok": False,
            "status": result["status"],
            "message": result["message"],
            "matches": result["matches"],
            "sync": result["sync"],
            "protected": result["protected"],
            "address": result["address"],
            "offset": result["offset"],
            "windows_scanned": result["windows_scanned"],
            "survivors": result["survivors"],
            "malformed": result["malformed"],
            "dump_partial": result["dump_partial"],
          })
      except Exception as e:
        tb = traceback.format_exc()
        self._send_json({
          "ok": False,
          "status": "error",
          "message": f"{e}\n\n{tb}\n\n{PING_REPORT}",
          "traceback": tb,
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      finally:
        matcher_lock.release()
      return

    if path == "/api/uninstall":
      try:
        key_manager = KeyFileManager()
        key_was_installed = key_manager.installed_key is not None
        key_manager.uninstall_key()
        self._send_json({
          "ok": True,
          "title": "Key removed" if key_was_installed else "Key not installed",
          "message": "Installed key removed." if key_was_installed else "Nothing to remove.",
          **RebootManager.key_status_payload(),
        })
      except Exception as e:
        self._send_json({
          "ok": False,
          "error": "unexpected",
          "title": "Unexpected error",
          "message": str(e),
          "traceback": traceback.format_exc(),
          **RebootManager.key_status_payload(),
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      return

    if path == "/api/reboot":
      try:
        request = self._read_json_body()
        status, payload = run_reboot_action(str(request.get("action", "")))
        self._send_json(payload, status=status)
      except Exception as e:
        self._send_json({
          "ok": False,
          "error": "unexpected",
          "title": "Unexpected error",
          "message": str(e),
          "traceback": traceback.format_exc(),
          **RebootManager.key_status_payload(),
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      return

    if path == "/api/can-collect":
      if not start_can_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A CAN collection or another panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/dataflash-dump":
      if not start_dataflash_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A DataFlash dump or another panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/can-sniff":
      if not start_sniff_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/prog-probe":
      if not start_probe_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/dataflash-diag":
      if not start_diag_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/read-mem":
      if not start_readmem_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/ident-map":
      if not start_ident_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/reset-probe":
      if not start_reset_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/level3-probe":
      if not start_level3_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/uds-sweep":
      if not start_sweep_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/ready-capture":
      if not start_ready_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/preamble-probe":
      if not start_preamble_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/sendkey-probe":
      if not start_sendkey_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/clear-cache":
      with can_lock:
        can_running = can_state["status"] == "running"
      with df_lock:
        df_running = df_state["status"] == "running"
      if can_running or df_running:
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A collection or dump is in progress. Wait for it to finish, then clear.",
        }, status=HTTPStatus.CONFLICT)
        return
      clear_can()
      clear_dataflash()
      self._send_json({"ok": True})
      return

    self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

  def _handle_request(self, send_body: bool) -> None:
    path = urlparse(self.path).path

    if path == "/api/health":
      self._send_json({
        "status": "ok",
        "service": "tsk_web",
        "host": HOST,
        "port": PORT,
        "url": get_tsk_url(),
        "addresses": get_ipv4_addresses(),
        "asset_dir": str(ASSET_DIR),
        "dry_run": not is_agnos(),
        "is_agnos": is_agnos(),
      }, send_body=send_body)
      return

    if path == "/api/status":
      self._send_json(RebootManager.key_status_payload(), send_body=send_body)
      return

    if path == "/api/can-status":
      with can_lock:
        payload = dict(can_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/dataflash-status":
      with df_lock:
        payload = dict(df_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/can-sniff-status":
      with sniff_lock:
        payload = dict(sniff_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/dataflash-diag-status":
      with diag_lock:
        payload = dict(diag_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/prog-probe-status":
      with probe_lock:
        payload = dict(probe_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/read-mem-status":
      with readmem_lock:
        payload = dict(readmem_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/ident-map-status":
      with ident_lock:
        payload = dict(ident_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/reset-probe-status":
      with reset_lock:
        payload = dict(reset_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/level3-status":
      with level3_lock:
        payload = dict(level3_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/sendkey-status":
      with sendkey_lock:
        payload = dict(sendkey_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/preamble-status":
      with preamble_lock:
        payload = dict(preamble_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/uds-sweep-status":
      with sweep_lock:
        payload = dict(sweep_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/ready-capture-status":
      with ready_lock:
        payload = dict(ready_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/reboot":
      try:
        self._send_json(get_reboot_actions_payload(), send_body=send_body)
      except Exception as e:
        self._send_json({
          "ok": False,
          "error": "unexpected",
          "title": "Unexpected error",
          "message": str(e),
          "traceback": traceback.format_exc(),
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR, send_body=send_body)
      return

    if path == "/favicon.ico":
      self.send_response(HTTPStatus.NO_CONTENT)
      self.end_headers()
      return

    asset = resolve_asset(path)
    if asset is not None:
      self._send_bytes(HTTPStatus.OK, content_type_for(asset), asset.read_bytes(), send_body=send_body)
      return

    self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND, send_body=send_body)

  def _send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK, send_body: bool = True) -> None:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    self._send_bytes(status, "application/json; charset=utf-8", body, send_body=send_body)

  def _read_json_body(self) -> dict:
    length = int(self.headers.get("Content-Length", "0") or "0")
    if length <= 0:
      return {}
    raw_body = self.rfile.read(length)
    if not raw_body:
      return {}
    return json.loads(raw_body.decode("utf-8"))

  def _send_bytes(self, status: HTTPStatus, content_type: str, body: bytes, send_body: bool = True) -> None:
    self.send_response(status)
    self.send_header("Content-Type", content_type)
    self.send_header("Content-Length", str(len(body)))
    self.send_header("Cache-Control", "no-store")
    self.end_headers()
    if send_body:
      self.wfile.write(body)

  def log_message(self, fmt: str, *args: object) -> None:
    return


class TSKWebServer(ThreadingHTTPServer):
  allow_reuse_address = True
  daemon_threads = True


def main() -> None:
  setup()
  rehydrate_dataflash_state()
  rehydrate_can_state()
  update_offroad_alert()
  threading.Thread(target=offroad_alert_loop, name="tsk_offroad_alert", daemon=True).start()

  server = TSKWebServer((HOST, PORT), TSKWebHandler)
  print(f"TSK Manager Web listening on http://{HOST}:{PORT}", flush=True)
  for ip in get_ipv4_addresses():
    print(f"TSK Manager Web detected address: http://{ip}:{PORT}", flush=True)

  try:
    server.serve_forever()
  except KeyboardInterrupt:
    pass
  finally:
    server.server_close()


if __name__ == "__main__":
  main()
