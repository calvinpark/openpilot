#!/usr/bin/env python3
"""READY-mode pass — the things only READY can give, in a 5-minute window.

Runs after the Not Ready to Drive sweep (`sweep_uds.py`), which writes the work-list this
pass reads. Two jobs:

1. **Full-payload CAN capture — the headline.** Nobody knows which arbitration IDs the
   Corolla signs with SecOC. The Sienna's protected IDs (0x2E4/0x131/0x344) are absent on
   every Corolla bus, and `sniff_can.py` records frame counts and arb IDs but never
   payloads, so it cannot answer this. Any future matcher oracle needs those IDs, so
   capturing them now removes a whole in-car trip later. The EPS only signs in READY —
   bus 1 carries 147 IDs there versus 2 in Not Ready to Drive — so this is categorically
   READY-only.

   Everything is written raw to `ready_capture.ndjson`; the analysis is entirely offline
   afterwards. SecOC frames give themselves away structurally: trailing bytes carrying a
   truncated MAC that changes every frame while the leading signal bytes stay stable or
   move slowly. The same file holds the 0x0F sync frames, which give the freshness
   counter's rate, width and rollover — also required by a matcher, also unknown today.

2. **Mode diff.** Three buckets from the Not Ready to Drive sweep get re-asked here:
   everything silent, everything that returned a *condition* NRC (0x22/0x7e/0x7f — those
   literally say "not in this state"), and the reprogramming set regardless of what the
   first pass said. Anything whose answer changes with drivability is the lever. If the
   reprogramming set is silent in both modes, drivability is eliminated as a variable.

   The address sweep repeats here for the same reason: far more modules are awake in
   READY, so "who else is on this bus, and do they go silent on the same services" gets a
   better answer. The 2026-07-25 Not Ready to Drive run found 13 responders, of which only
   0x7f1 answers the four silent services — which does not by itself distinguish per-ECU
   behaviour from a per-destination gateway policy, since a gateway filters by destination
   and would answer for itself. The capture in this same pass is what settles it: a module
   that answers diagnostics but never transmits periodic frames on our segment is being
   proxied, and a repin would then bypass the filter. See COROLLA_INVESTIGATION.md 9.9.

READY means the car is drivable, so this pass sends only requests the first sweep already
characterised, never unknown bytes. Unknown bytes belong in Not Ready to Drive, where a
surprise is harmless.

is_agnos-gated; the server mocks it off-device.
"""
import json
import os
import time

from tsk.lib.env import CACHE_DIR, is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.dump_dataflash import ADDR
from tsk.lib.dump_diag import CANDIDATE_BUSES
from tsk.lib.sweep_uds import (
  ADDRESS_RANGE, SILENT_SET, SWEEP_PATH, ask, summarize,
)

CAPTURE_DIR = f"{CACHE_DIR}/tsk/uds-sweep"
CAPTURE_PATH = f"{CAPTURE_DIR}/ready_capture.ndjson"
DIFF_PATH = f"{CAPTURE_DIR}/ready_diff.ndjson"

DEFAULT_BUDGET = 300.0
CAPTURE_SECONDS = 90.0        # long enough for the freshness counter to show its period
TIMEOUT = 0.2
SYNC_ADDR = 0x0F              # the Sienna's SecOC sync ID; present on the Corolla too


def _noop(**kwargs) -> None:
  pass


def analyze_capture(frames: list, min_samples: int = 8) -> dict:
  """Pure — flag the arbitration IDs that look SecOC-signed.

  frames: [(bus, addr, hexpayload), ...]. A signed frame carries a truncated MAC in its
  trailing bytes: those bytes differ on nearly every sample while the leading signal
  bytes repeat. Scoring the tail's distinct-value ratio against the head's separates them
  without knowing the DBC. Off-device testable.
  """
  by_id: dict = {}
  for bus, addr, payload in frames:
    by_id.setdefault((bus, addr), []).append(payload)

  out = {"candidates": [], "sync": [], "ids": len(by_id), "frames": len(frames)}
  for (bus, addr), samples in sorted(by_id.items()):
    if addr == SYNC_ADDR:
      out["sync"].append({"bus": bus, "addr": f"0x{addr:03x}", "samples": len(samples),
                          "distinct": len(set(samples))})
      continue
    if len(samples) < min_samples:
      continue
    width = min(len(s) for s in samples) // 2
    if width < 4:
      continue
    tail = [s[-8:] for s in samples]          # last 4 bytes
    head = [s[:-8] for s in samples]
    tail_ratio = len(set(tail)) / len(tail)
    head_ratio = len(set(head)) / len(head)
    if tail_ratio >= 0.9 and tail_ratio - head_ratio >= 0.3:
      out["candidates"].append({
        "bus": bus, "addr": f"0x{addr:03x}", "samples": len(samples),
        "tail_distinct": round(tail_ratio, 3), "head_distinct": round(head_ratio, 3),
      })
  out["candidates"].sort(key=lambda c: -c["samples"])
  return out


def capture_ready(progress_cb=None, budget_seconds: float = DEFAULT_BUDGET) -> dict:
  """Run the READY pass. Returns:
    {status, panda, eps_bus, capture{}, diff[], responders[], cross[], seeds[],
     frames, message}
  status is "captured" | "no_sweep" | "unreachable" | "failed".
  Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop
  started = time.time()

  def remaining() -> float:
    return budget_seconds - (time.time() - started)

  diff: list = []
  responders: list = []
  cross: list = []
  seeds: list = []
  result = {
    "status": "failed", "panda": "", "eps_bus": -1, "capture": {}, "diff": diff,
    "responders": responders, "cross": cross, "seeds": seeds, "frames": 0, "message": "",
  }

  from opendbc.car.structs import CarParams

  import subprocess
  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)

  try:
    panda = TSKExtractor._connect_panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    try:
      ver = panda.get_version()
      result["panda"] = ver.decode(errors="replace") if isinstance(ver, (bytes, bytearray)) else str(ver)
    except Exception:
      result["panda"] = "unknown"
  except Exception as e:
    result["message"] = f"Connect failed: {type(e).__name__}: {e}"
    return result

  os.makedirs(CAPTURE_DIR, exist_ok=True)
  rx_of = lambda tx: tx + 8

  # --- 1. full-payload capture, every bus, every ID -------------------------------
  frames: list = []
  try:
    with open(CAPTURE_PATH, "w") as fh:
      window = min(CAPTURE_SECONDS, max(10.0, remaining() - 120.0))
      begin = time.time()
      last_report = 0.0
      while time.time() - begin < window:
        try:
          batch = panda.can_recv()
        except Exception:
          break
        for addr, *_rest, data, bus in batch:
          if bus >= 0x80:
            continue
          payload = bytes(data).hex()
          frames.append((bus, addr, payload))
          fh.write(json.dumps({"t": round(time.time() - begin, 4), "bus": bus,
                               "addr": addr, "data": payload}) + "\n")
        now = time.time() - begin
        if now - last_report >= 2.0:
          last_report = now
          cb(steps=len(frames), last=f"capturing {int(now)}s / {int(window)}s",
             stage="capture")
      fh.flush()
  except Exception as e:
    result["message"] = f"Capture failed: {type(e).__name__}: {e}"

  result["frames"] = len(frames)
  result["capture"] = analyze_capture(frames)
  cb(steps=len(frames), last="capture analysed", stage="capture")

  # --- 2. find the EPS, then the mode diff ----------------------------------------
  eps_bus = None
  for cand in CANDIDATE_BUSES:
    r = ask(panda, cand, ADDR, rx_of(ADDR), b"\x10\x01", 0.3)
    if r["outcome"] in ("positive", "nrc"):
      eps_bus = cand
      break
  result["eps_bus"] = eps_bus if eps_bus is not None else -1

  if eps_bus is None:
    result.update(status="captured" if frames else "unreachable",
                  message=(f"Captured {len(frames)} frames, but the EPS did not answer "
                           "diagnostics on any bus in READY — the mode diff was skipped. "
                           "Screenshot and send to Calvin."))
    return result

  prior = summarize(SWEEP_PATH)
  worklist: list = []
  for payload, label in SILENT_SET:
    worklist.append((payload, f"reflash set: {label}"))
  for label in prior.get("silent", []):
    if label.startswith("service 0x"):
      sid = int(label.split("0x")[1], 16)
      worklist.append((bytes([sid]), f"silent in NRtD: {label}"))
  for label in prior.get("condition_nrc", []):
    if label.startswith("service 0x"):
      sid = int(label.split("0x")[1], 16)
      worklist.append((bytes([sid]), f"condition NRC in NRtD: {label}"))

  seen_req: set = set()
  with open(DIFF_PATH, "w") as fh:
    for payload, label in worklist:
      if remaining() <= 60:
        break
      if payload.hex() in seen_req:
        continue
      seen_req.add(payload.hex())
      ask(panda, eps_bus, ADDR, rx_of(ADDR), b"\x10\x03", TIMEOUT)
      r = ask(panda, eps_bus, ADDR, rx_of(ADDR), payload, TIMEOUT)
      entry = {"label": label, "request": payload.hex(), "outcome": r["outcome"],
               "nrc": r["nrc"], "raw": r["raw"]}
      diff.append(entry)
      fh.write(json.dumps(entry) + "\n")
      cb(steps=len(diff), last=label, stage="diff")
  if not prior.get("records"):
    result["message"] = "No Not Ready to Drive sweep on this device yet — the mode diff " \
                        "only re-tested the reprogramming set. "

  # --- 3. address sweep, where far more modules are awake -------------------------
  for a in ADDRESS_RANGE:
    if remaining() <= 25:
      break
    r = ask(panda, eps_bus, a, rx_of(a), b"\x10\x01", TIMEOUT)
    if r["outcome"] in ("positive", "nrc"):
      responders.append(f"0x{a:03x}")
  cb(steps=len(responders), last="address sweep", stage="addresses")

  # --- 4. the same silent services against every other responder ------------------
  for a_hex in list(responders):
    a = int(a_hex, 16)
    if a == ADDR or remaining() <= 10:
      continue
    for payload, label in SILENT_SET:
      r = ask(panda, eps_bus, a, rx_of(a), payload, TIMEOUT)
      cross.append({"addr": a_hex, "label": label, "outcome": r["outcome"],
                    "nrc": r["nrc"]})

  # --- 5. does security still hand out a seed in READY -----------------------------
  if remaining() > 5:
    ask(panda, eps_bus, ADDR, rx_of(ADDR), b"\x10\x03", TIMEOUT)
    for lvl in (0x01, 0x03):
      r = ask(panda, eps_bus, ADDR, rx_of(ADDR), bytes([0x27, lvl]), TIMEOUT)
      seeds.append({"level": f"0x{lvl:02x}", "outcome": r["outcome"], "nrc": r["nrc"],
                    "raw": r["raw"]})

  ask(panda, eps_bus, ADDR, rx_of(ADDR), b"\x10\x01", TIMEOUT)

  cand = len(result["capture"].get("candidates", []))
  changed = [d for d in diff if d["outcome"] != "silent"]
  result.update(
    status="captured",
    message=(result.get("message", "") +
             f"Captured {len(frames)} frames across {result['capture'].get('ids', 0)} IDs; "
             f"{cand} look SecOC-signed. Mode diff: {len(changed)} of {len(diff)} answered "
             f"in READY that did not in Not Ready to Drive. {len(responders)} responder(s) "
             "on the bus. Screenshot and send to Calvin — the capture file is saved on the "
             "device for offline analysis."))
  return result
