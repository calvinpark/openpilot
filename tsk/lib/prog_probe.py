#!/usr/bin/env python3
"""Programming-session probe: try several ways to enter the UDS PROGRAMMING session
on an EPS that answers DEFAULT/EXTENDED but times out on PROGRAMMING.

Built for the 2025 Corolla Hybrid (EPS 8965F1208000), which the sweep reached on bus 1
and which grants default/extended sessions but does not answer the programming-session
request. Each sequence resets to DEFAULT first and records the PROGRAMMING outcome
(accepted | NRC | timeout), so one run tests every plausible entry path. The security
attempt runs last: a failed key can trip a temporary security lockout on some ECUs.

Read intent only — the payload is never uploaded or triggered here. The one write is the
security SEND_KEY in the last sequence (the Willem key, expected to be rejected on a
non-family EPS), which is what tells us whether programming is gated behind security.
"""
import time
import traceback as _tb

from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.dump_dataflash import ADDR
from tsk.lib.dump_diag import CANDIDATE_BUSES

LONG_TIMEOUT = 3.0    # patience for an EPS that resets into its bootloader on PROGRAMMING


def _noop(**kwargs) -> None:
  pass


def probe_programming(progress_cb=None) -> dict:
  """Run the programming-session entry matrix. Returns:
    {status, panda, eps_bus, attempts[], security{}, message}
  status is "entered" (some sequence reached PROGRAMMING) | "blocked" | "unreachable" |
  "failed". Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from Crypto.Cipher import AES
  from opendbc.car.structs import CarParams
  from opendbc.car.uds import UdsClient, ACCESS_TYPE, SESSION_TYPE, \
    InvalidServiceIdError, MessageTimeoutError, NegativeResponseError
  try:
    from opendbc.car.uds import _negative_response_codes as NRC_TABLE
  except Exception:
    NRC_TABLE = {}

  attempts: list = []
  result = {
    "status": "failed", "panda": "", "eps_bus": -1, "attempts": attempts,
    "security": {}, "message": "",
  }

  def nrc(code) -> str:
    return f"NRC 0x{code:02x} {NRC_TABLE.get(code, 'unknown')}"

  # Kill the manager so pandad doesn't fight for the panda (mirrors the other jobs).
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

  def mk(bus, timeout):
    return UdsClient(panda, ADDR, ADDR + 8, bus, timeout=timeout, response_pending_timeout=timeout)

  # Find the EPS bus: first candidate that answers a default-session request.
  eps_bus = None
  for cand in CANDIDATE_BUSES:
    try:
      mk(cand, 0.3).diagnostic_session_control(SESSION_TYPE.DEFAULT)
      eps_bus = cand
      break
    except NegativeResponseError:
      eps_bus = cand  # a negative response still means the EPS is on this bus
      break
    except Exception:
      continue
  result["eps_bus"] = eps_bus if eps_bus is not None else -1
  if eps_bus is None:
    result.update(status="unreachable",
                  message="EPS did not answer on bus 0, 1, or 2 in this car state.")
    return result

  def reset_default():
    try:
      mk(eps_bus, 0.5).diagnostic_session_control(SESSION_TYPE.DEFAULT)
    except Exception:
      pass
    time.sleep(0.2)

  def record(name, ok, detail):
    attempts.append({"name": name, "ok": ok, "detail": detail})
    cb(attempts=len(attempts), last=name)

  def attempt(name, fn):
    # Reset to a clean default session, run the sequence, and record how its final
    # PROGRAMMING request fared. Never raises.
    reset_default()
    try:
      fn()
      record(name, True, "PROGRAMMING accepted")
    except NegativeResponseError as e:
      record(name, False, nrc(e.error_code))
    except (InvalidServiceIdError, MessageTimeoutError) as e:
      record(name, False, f"{type(e).__name__}: {e}" if str(e) else type(e).__name__)
    except Exception as e:
      record(name, False, f"{type(e).__name__}: {e}" if str(e) else type(e).__name__)

  # 1. EXTENDED then PROGRAMMING, patient timeout.
  def seq_patient():
    u = mk(eps_bus, LONG_TIMEOUT)
    u.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    time.sleep(0.7)
    u.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
  attempt("extended -> programming (3s)", seq_patient)

  # 2. Double PROGRAMMING with a 1s settle, mirroring the Sienna production flow. The
  # first request may go unanswered while the EPS switches contexts; the second counts.
  def seq_double():
    u = mk(eps_bus, LONG_TIMEOUT)
    u.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    time.sleep(0.7)
    try:
      u.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
    except Exception:
      pass
    time.sleep(1.0)
    u.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
  attempt("double programming (1s settle)", seq_double)

  # 3. Straight to PROGRAMMING from default, skipping EXTENDED.
  def seq_direct():
    mk(eps_bus, LONG_TIMEOUT).diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
  attempt("default -> programming direct", seq_direct)

  # 4. Tester-present keepalive, then PROGRAMMING.
  def seq_tp():
    u = mk(eps_bus, LONG_TIMEOUT)
    u.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    u.tester_present()
    time.sleep(0.3)
    u.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
  attempt("tester-present -> programming", seq_tp)

  # 5. Security-first (LAST — a failed key can trip a temporary lockout). Capture the
  # seed and whether the Willem key is accepted, then try PROGRAMMING behind it.
  reset_default()
  sec = {"seed": "", "send_key": "", "programming": ""}
  try:
    u = mk(eps_bus, LONG_TIMEOUT)
    u.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    seed = u.security_access(ACCESS_TYPE.REQUEST_SEED, data_record=b"\x00" * 16)
    sec["seed"] = bytes(seed).hex()
    try:
      derived = AES.new(TSKExtractor.SEED_KEY_SECRET, AES.MODE_ECB).decrypt(b"\x00" * 16)
      sent = AES.new(derived, AES.MODE_ECB).encrypt(bytes(seed))
      u.security_access(ACCESS_TYPE.SEND_KEY, sent)
      sec["send_key"] = "accepted"
      try:
        u.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
        sec["programming"] = "accepted"
        record("security-first -> programming", True, "PROGRAMMING accepted after security")
      except NegativeResponseError as e:
        sec["programming"] = nrc(e.error_code)
        record("security-first -> programming", False, sec["programming"])
      except Exception as e:
        sec["programming"] = type(e).__name__
        record("security-first -> programming", False, type(e).__name__)
    except NegativeResponseError as e:
      sec["send_key"] = nrc(e.error_code)
      record("security-first -> programming", False, f"send_key {sec['send_key']}")
  except NegativeResponseError as e:
    sec["seed"] = nrc(e.error_code)
    record("security-first -> programming", False, f"request_seed {sec['seed']}")
  except Exception as e:
    record("security-first -> programming", False, f"{type(e).__name__}: {e}" if str(e) else type(e).__name__)
  result["security"] = sec

  entered = any(a["ok"] for a in attempts)
  result["status"] = "entered" if entered else "blocked"
  if entered:
    hit = next(a["name"] for a in attempts if a["ok"])
    result["message"] = f"A programming-session sequence worked: {hit}. The exploit path may be open — tell Calvin."
  else:
    result["message"] = ("No sequence entered the programming session on bus "
                         f"{eps_bus}. The entry sequence for this EPS is unknown — "
                         "the firmware-dump path is next.")
  return result
