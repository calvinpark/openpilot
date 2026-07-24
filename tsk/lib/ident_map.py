#!/usr/bin/env python3
"""EPS identity block + service-surface map — read-only characterization of an unknown EPS.

Two purposes in one read-only pass: the full identification block (part number, software
and hardware versions, supplier, VIN) names the exact variant for sourcing a bench module,
and the service map shows which UDS services this firmware answers (supported vs
serviceNotSupported) — e.g. whether ReadMemoryByAddress or security access is even present.

Deliberately read-only. The service probe only touches services that are safe to send even
if the EPS accepts them: session control, read-data-by-id, read-memory, security seed
request, tester-present, read-DTC. The destructive services — ECU reset, write-DID, routine
control, download/upload, clear-DTC — are NOT probed here (the reset has its own dedicated
probe). Off-device raises NotAGNOSError; the server mocks it.
"""
import subprocess
import time

from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.dump_dataflash import ADDR, DUMP_START
from tsk.lib.dump_diag import CANDIDATE_BUSES

MAP_TIMEOUT = 1.0

# Full identification block (ISO 14229 0xF18x/0xF19x). Each read is independent so one
# rejection doesn't stop the sweep. 0xF181 app-sw-id and 0xF187 spare-part carry the
# 8965... variant string; 0xF186 is the active session (shared with did-it-take).
IDENTITY_DIDS = [
  (0xF180, "boot_sw_id"),
  (0xF181, "app_sw_id"),
  (0xF182, "app_data_id"),
  (0xF183, "boot_fingerprint"),
  (0xF184, "app_fingerprint"),
  (0xF186, "active_session"),
  (0xF187, "spare_part_no"),
  (0xF188, "ecu_sw_no"),
  (0xF189, "ecu_sw_ver"),
  (0xF18A, "supplier_id"),
  (0xF18B, "mfg_date"),
  (0xF18C, "ecu_serial"),
  (0xF190, "vin"),
  (0xF191, "mfr_ecu_hw_no"),
  (0xF192, "supplier_hw_no"),
  (0xF193, "supplier_hw_ver"),
  (0xF194, "supplier_sw_no"),
  (0xF195, "supplier_sw_ver"),
]


def _noop(**kwargs) -> None:
  pass


def _ascii(b: bytes) -> str:
  return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def map_surface(progress_cb=None) -> dict:
  """Read the identity block and probe the safe UDS service set. Returns:
    {status, panda, eps_bus, identity[], services[], message}
  status is "mapped" | "unreachable" | "failed". Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from opendbc.car.structs import CarParams
  from opendbc.car.uds import UdsClient, ACCESS_TYPE, SESSION_TYPE, SERVICE_TYPE, \
    InvalidServiceIdError, MessageTimeoutError, NegativeResponseError
  try:
    from opendbc.car.uds import _negative_response_codes as NRC_TABLE
  except Exception:
    NRC_TABLE = {}

  identity: list = []
  services: list = []
  result = {"status": "failed", "panda": "", "eps_bus": -1, "identity": identity,
            "services": services, "message": ""}

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

  u = mk(eps_bus, MAP_TIMEOUT)
  try:
    u.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
  except Exception:
    pass

  # Identity sweep — independent reads, never stops the run.
  for did, label in IDENTITY_DIDS:
    entry = {"did": f"0x{did:04x}", "name": label}
    try:
      data = bytes(u.read_data_by_identifier(did))
      entry.update(hex=data.hex(), ascii=_ascii(data))
    except NegativeResponseError as e:
      entry.update(hex="", ascii=nrc(e.error_code))
    except Exception as e:
      entry.update(hex="", ascii=type(e).__name__)
    identity.append(entry)
    cb(items=len(identity) + len(services), last=f"id {label}")

  # Service-surface map — safe services only. A positive response or any NRC other than
  # serviceNotSupported (0x11) means the service is present; 0x11 means it is not.
  def classify(fn):
    try:
      fn()
      return True, "supported"
    except NegativeResponseError as e:
      if e.error_code == 0x11:
        return False, "not supported (0x11)"
      if e.error_code == 0x7f:
        return True, "supported (not in this session)"
      return True, f"supported ({nrc(e.error_code)})"
    except (InvalidServiceIdError, MessageTimeoutError):
      return None, "no response"
    except Exception as e:
      return None, type(e).__name__

  probes = [
    ("0x10 session control", lambda: u.diagnostic_session_control(SESSION_TYPE.DEFAULT)),
    ("0x22 read data by id", lambda: u.read_data_by_identifier(0xF181)),
    ("0x23 read memory", lambda: u.read_memory_by_address(DUMP_START, 0x04)),
    ("0x27 security access", lambda: u.security_access(ACCESS_TYPE.REQUEST_SEED, data_record=b"\x00" * 16)),
    ("0x3e tester present", lambda: u.tester_present()),
    ("0x19 read DTC info", lambda: u._uds_request(SERVICE_TYPE.READ_DTC_INFORMATION, subfunction=0x01, data=b"\xff")),
  ]
  # After the security seed request, re-enter extended so a later probe isn't skewed by
  # a lingering security state (harmless, but keeps each probe independent).
  for name, fn in probes:
    supported, detail = classify(fn)
    services.append({"name": name, "supported": supported, "detail": detail})
    cb(items=len(identity) + len(services), last=name)
    try:
      u.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except Exception:
      pass

  result["status"] = "mapped"
  reads_ok = sum(1 for e in identity if e.get("hex"))
  svc_ok = sum(1 for s in services if s["supported"])
  result["message"] = (f"Read {reads_ok} identity field(s); {svc_ok} of {len(services)} probed "
                       "services answered. Screenshot all of it and send to Calvin.")
  return result
