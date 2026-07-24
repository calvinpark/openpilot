#!/usr/bin/env python3
"""ReadMemoryByAddress (UDS 0x23) probe: ask the EPS to read its own DataFlash
directly — no programming session, no exploit.

The whole Willem dump exists because normal reads are blocked on the Sienna EPS: the
shellcode blasts memory out as CAN frames precisely because 0x23 is denied there. But
the Corolla EPS (8965F1208000) is a different firmware family with an unmapped service
surface, so it costs one read to check whether 0x23 is open here. If it is, the key
region reads out with no programming session at all and the whole wall stops mattering.

Read intent only: 0x23 is a read service, no write, no session change past DEFAULT/
EXTENDED, no security key sent. Off-device raises NotAGNOSError; the server mocks it.
Shares the panda-takeover preamble and the EPS-bus sweep with the other diagnostics.
"""
import subprocess
import time

from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.dump_dataflash import ADDR, DUMP_START, KNOWN_KEY_OFFSET, PAYLOAD_LOAD_ADDR
from tsk.lib.dump_diag import CANDIDATE_BUSES

KEY_ADDR = DUMP_START + KNOWN_KEY_OFFSET   # 0xFF206E14 — the Sienna/Yaris key offset
READ_SIZE = 0x10                           # 16 bytes: exactly one SecOC key
READ_TIMEOUT = 1.0

# (label, address, size). The key region first — a hit there is the whole game. The
# DataFlash base and a RAM address are controls: together they separate "0x23 reads
# the flash region" from "0x23 is refused everywhere".
TARGETS = [
  ("key region", KEY_ADDR, READ_SIZE),
  ("dataflash base", DUMP_START, READ_SIZE),
  ("ram (control)", PAYLOAD_LOAD_ADDR, READ_SIZE),
]


def _noop(**kwargs) -> None:
  pass


def read_key_region(progress_cb=None) -> dict:
  """Probe 0x23 at the key region and two control addresses in EXTENDED, then the key
  region again in DEFAULT. Returns:
    {status, panda, eps_bus, reads[], message}
  status is "read" (some address returned bytes) | "denied" (every address NRC/timeout)
  | "unreachable" | "failed". Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from opendbc.car.structs import CarParams
  from opendbc.car.uds import UdsClient, SESSION_TYPE, \
    InvalidServiceIdError, MessageTimeoutError, NegativeResponseError
  try:
    from opendbc.car.uds import _negative_response_codes as NRC_TABLE
  except Exception:
    NRC_TABLE = {}

  reads: list = []
  result = {"status": "failed", "panda": "", "eps_bus": -1, "reads": reads, "message": ""}

  def nrc(code) -> str:
    return f"NRC 0x{code:02x} {NRC_TABLE.get(code, 'unknown')}"

  # Kill the manager so pandad doesn't fight for the panda (mirrors the other jobs).
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

  def mk(bus):
    return UdsClient(panda, ADDR, ADDR + 8, bus, timeout=READ_TIMEOUT, response_pending_timeout=READ_TIMEOUT)

  # Find the EPS bus: first candidate that answers a default-session request. A
  # negative response still means the EPS is on that bus and talking.
  eps_bus = None
  for cand in CANDIDATE_BUSES:
    try:
      UdsClient(panda, ADDR, ADDR + 8, cand, timeout=0.3, response_pending_timeout=0.3) \
        .diagnostic_session_control(SESSION_TYPE.DEFAULT)
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

  def do_read(name, session_name, session, addr, size):
    u = mk(eps_bus)
    try:
      u.diagnostic_session_control(session)
    except Exception:
      pass
    entry = {"name": name, "session": session_name, "address": f"0x{addr:08x}", "size": size}
    try:
      data = u.read_memory_by_address(addr, size)
      entry.update(ok=True, detail=bytes(data).hex())
    except NegativeResponseError as e:
      entry.update(ok=False, detail=nrc(e.error_code))
    except (InvalidServiceIdError, MessageTimeoutError) as e:
      entry.update(ok=False, detail=f"{type(e).__name__}: {e}" if str(e) else type(e).__name__)
    except Exception as e:
      entry.update(ok=False, detail=f"{type(e).__name__}: {e}" if str(e) else type(e).__name__)
    reads.append(entry)
    cb(reads=len(reads), last=f"{name} ({session_name})")

  # EXTENDED for all three targets, then the key region again in DEFAULT to show
  # whether a hit (or the denial) is session-gated.
  for name, addr, size in TARGETS:
    do_read(name, "extended", SESSION_TYPE.EXTENDED_DIAGNOSTIC, addr, size)
  do_read("key region", "default", SESSION_TYPE.DEFAULT, KEY_ADDR, READ_SIZE)

  got = any(r["ok"] for r in reads)
  result["status"] = "read" if got else "denied"
  if got:
    hit = next(r for r in reads if r["ok"])
    result["message"] = (f"0x23 returned data at {hit['address']} ({hit['session']}). If that is the "
                         "key region, the key may be readable with no programming session — "
                         "screenshot and send to Calvin.")
  else:
    result["message"] = ("0x23 was refused at every address — the EPS does not allow direct memory "
                         "reads here, so the exploit path is still needed.")
  return result
