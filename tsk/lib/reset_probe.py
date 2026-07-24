#!/usr/bin/env python3
"""Reset-window probe: hard-reset the EPS, then hammer the PROGRAMMING request through
the reboot in case programming is only accepted in the post-reset bootloader window.

Some ECUs grant the programming session only in a brief bootloader window right after a
reset, before the application image takes over. The Corolla EPS answers DEFAULT/EXTENDED
but goes silent on PROGRAMMING in steady state; this checks whether a reset opens a window
the steady-state probe misses. It reads the active session (0xF186) afterward to catch a
silent switch — programming entered but the response lost.

The one write is ECU reset (service 0x11), which reboots the EPS — safe parked in Not
Ready To Drive (the EPS re-inits like a normal power cycle), never while moving. No
payload, no security key sent. Off-device raises NotAGNOSError; the server mocks it.
"""
import subprocess
import time

from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.dump_dataflash import ADDR
from tsk.lib.dump_diag import CANDIDATE_BUSES

HAMMER_SECONDS = 4.0    # cover the reboot + bootloader window
SHORT_TIMEOUT = 0.25    # each PROGRAMMING attempt during the window
ACTIVE_SESSION_DID = 0xF186


def _noop(**kwargs) -> None:
  pass


def probe_reset_window(progress_cb=None) -> dict:
  """Reset the EPS and hammer PROGRAMMING through the reboot. Returns:
    {status, panda, eps_bus, reset, attempts[], session_after, message}
  status is "entered" (PROGRAMMING accepted in the window) | "blocked" | "unreachable" |
  "failed". Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from opendbc.car.structs import CarParams
  from opendbc.car.uds import UdsClient, RESET_TYPE, SESSION_TYPE, \
    InvalidServiceIdError, MessageTimeoutError, NegativeResponseError
  try:
    from opendbc.car.uds import _negative_response_codes as NRC_TABLE
  except Exception:
    NRC_TABLE = {}

  attempts: list = []
  result = {"status": "failed", "panda": "", "eps_bus": -1, "reset": "",
            "attempts": attempts, "session_after": "", "message": ""}

  def nrc(code) -> str:
    return f"NRC 0x{code:02x} {NRC_TABLE.get(code, 'unknown')}"

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

  eps_bus = None
  for cand in CANDIDATE_BUSES:
    try:
      mk(cand, 0.3).diagnostic_session_control(SESSION_TYPE.DEFAULT)
      eps_bus = cand
      break
    except NegativeResponseError:
      eps_bus = cand
      break
    except Exception:
      continue
  result["eps_bus"] = eps_bus if eps_bus is not None else -1
  if eps_bus is None:
    result.update(status="unreachable", message="EPS did not answer on bus 0, 1, or 2 in this car state.")
    return result

  # Extended session, then hard reset.
  try:
    mk(eps_bus, 1.0).diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
  except Exception:
    pass
  try:
    mk(eps_bus, 1.0).ecu_reset(RESET_TYPE.HARD)
    result["reset"] = "hard reset accepted"
  except NegativeResponseError as e:
    result["reset"] = nrc(e.error_code)
  except Exception as e:
    result["reset"] = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__

  # Immediately hammer PROGRAMMING through the reboot window. First acceptance wins;
  # timeouts (EPS still rebooting) are recorded sparsely to keep the list legible.
  entered = False
  begin = time.time()
  n = 0
  while time.time() - begin < HAMMER_SECONDS:
    n += 1
    ms = int((time.time() - begin) * 1000)
    try:
      mk(eps_bus, SHORT_TIMEOUT).diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
      attempts.append({"t_ms": ms, "detail": "PROGRAMMING accepted"})
      cb(attempts=len(attempts), last=f"{ms}ms accepted")
      entered = True
      break
    except NegativeResponseError as e:
      attempts.append({"t_ms": ms, "detail": nrc(e.error_code)})
      cb(attempts=len(attempts), last=f"{ms}ms nrc")
    except (InvalidServiceIdError, MessageTimeoutError):
      if n % 5 == 1:
        attempts.append({"t_ms": ms, "detail": "timeout"})
        cb(attempts=len(attempts), last=f"{ms}ms timeout")
    except Exception as e:
      attempts.append({"t_ms": ms, "detail": type(e).__name__})
      cb(attempts=len(attempts), last=f"{ms}ms err")

  # Read the active session to catch a silent switch (programming entered, response lost).
  try:
    data = bytes(mk(eps_bus, 1.0).read_data_by_identifier(ACTIVE_SESSION_DID))
    result["session_after"] = f"0x{data[0]:02x}" if data else "empty"
  except NegativeResponseError as e:
    result["session_after"] = nrc(e.error_code)
  except Exception as e:
    result["session_after"] = type(e).__name__

  result["status"] = "entered" if entered else "blocked"
  if entered:
    hit = next(a for a in attempts if "accepted" in a["detail"])
    result["message"] = (f"PROGRAMMING accepted {hit['t_ms']}ms after reset — there is a post-reset "
                         "window. Screenshot and send to Calvin.")
  else:
    result["message"] = ("No PROGRAMMING acceptance in the reset window. Active session after reset: "
                         f"{result['session_after']} (0x02 would mean it switched silently).")
  return result
