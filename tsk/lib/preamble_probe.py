#!/usr/bin/env python3
"""Pre-programming preamble probe — one in-car run, everything a single session can answer.

Built for the 2025 Corolla Hybrid (EPS 8965F1208000, bus 1), which answers DEFAULT and
EXTENDED but is silent on PROGRAMMING. Every prior probe entered PROGRAMMING cold. OEM
reflash tools never do: they quiesce the bus first — ControlDTCSetting OFF (0x85) and
CommunicationControl disable-normal-tx (0x28) — and many ECUs refuse or ignore a
programming request while normal messaging is live. prog_probe's five sequences never
sent either service, so the preamble family is untested.

Each in-car session costs Spanconstant real effort and the EPS drops out of its
diagnostic-responsive state after a burst, so this run front-loads value: the cheapest,
most-answering steps first, everything recorded incrementally, and a liveness check
between blocks so a null tail is attributable to the EPS dropping out rather than to a
refusal.

Blocks, in order:

  A. baseline    — bus sweep, app_sw_id / ecu_serial / active session.
  B. lock read   — bare 0x03 REQUEST_SEED as the FIRST security op. Answers whether the
                   15:16 send-key (NRC 0x35) left a persistent lock, which nothing has
                   measured. A seed rules out a persistent lock; 0x36/0x37 means locked
                   and the run stops there. Also takes the 0x01 baseline (expect 0x7e)
                   that block D compares against.
  C. surface     — the services Willem's exploit needs, by refusal code only: DIDs
                   0x201/0x202/0x203 read, RoutineControl REQUEST_RESULTS on 0x10f0,
                   RequestDownload to RAM, and whether 0x85 / 0x28 are accepted at all.
                   0x7f (not in this session) means the service exists and is gated;
                   0x11 (service not supported) means the exploit path is absent on this
                   EPS even with PROGRAMMING open. Then the DTC snapshot.
  D. preamble    — five PROGRAMMING entries, each from a fresh DEFAULT -> EXTENDED, each
                   followed by an 0xF186 session read AND a 0x01 REQUEST_SEED retry. If
                   0x01 ever hands out a seed, Willem's secret becomes testable at the
                   level it actually belongs to (0x01/0x02) — that is the run's best
                   possible outcome and it costs no counted attempt to detect.
  E. dtc diff    — a second snapshot, diffed. A fresh code names the unmet condition; an
                   empty diff alongside bus silence points at a lower-layer drop
                   (ISO-TP, addressing, gateway) rather than an application refusal.
                   Nothing so far separates those two.
  F. reads       — 0x23 retried at the Sienna key region / dataflash base / RAM, in case
                   the preamble widened the range. Then a final liveness read.

No key is ever sent and no counter is touched: REQUEST_SEED is a challenge request, not
an attempt. 0x85 and 0x28 are restored (DTC ON, RX/TX enabled) plus a DEFAULT session in
a finally, and a power cycle restores them independently. 0x85 is ordered before 0x28
throughout — DTC-off first is why OEM tools sequence it that way, it suppresses the
lost-message codes other ECUs would set while EPS tx is disabled.

The EPS bus is found by the same software sweep the other tools use (no pin swap).
is_agnos-gated; the server mocks it off-device.
"""
import time

from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.dump_dataflash import ADDR, DUMP_START, KNOWN_KEY_OFFSET
from tsk.lib.dump_diag import CANDIDATE_BUSES

SHORT_TIMEOUT = 1.0
LONG_TIMEOUT = 3.0
PATIENT_TIMEOUT = 6.0     # one variant waits longer, in case PROGRAMMING reboots into a
                          # bootloader that needs time before it answers
FUNCTIONAL_ADDR = 0x7DF
ACTIVE_SESSION_DID = 0xF186
SEED_DATA = b"\x00" * 16

SEED_LEVEL_WILLEM = 0x01  # the level Willem's Sienna secret belongs to (gated behind PROGRAMMING)
SEED_LEVEL_EXT = 0x03     # the level the Corolla hands out in EXTENDED

# Raw requests we send outside UdsClient, where we do not want its response handling.
PROGRAMMING_REQUEST = b"\x10\x02"
PROGRAMMING_SUPPRESS = b"\x10\x82"          # suppressPosRsp — we read 0xF186 instead of waiting
COMM_CONTROL_DISABLE_TX = b"\x28\x01\x01"   # ENABLE_RX_DISABLE_TX, NORMAL message type

# Willem's exploit surface, probed by refusal code only — no writes, no transfers.
EXPLOIT_DIDS = [(0x201, "did_201_key"), (0x202, "did_202_iv"), (0x203, "did_203_state")]
VERIFY_ROUTINE = 0x10F0
PAYLOAD_RAM_ADDR = 0xFEBF0000
PAYLOAD_RAM_SIZE = 0x1000

KEY_REGION = DUMP_START + KNOWN_KEY_OFFSET   # 0xFF206E14
READ_TARGETS = [
  ("key region", KEY_REGION),
  ("dataflash base", DUMP_START),
  ("ram window", PAYLOAD_RAM_ADDR),
]


def _noop(**kwargs) -> None:
  pass


def _ascii(b: bytes) -> str:
  return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def _parse_dtcs(data: bytes) -> list:
  """DTC_BY_STATUS_MASK response: [availability mask] + N x (3-byte DTC + 1-byte status)."""
  out = []
  body = data[1:] if data else b""
  for i in range(0, len(body) - 3, 4):
    code = int.from_bytes(body[i:i + 3], "big")
    out.append(f"{code:06x}:{body[i + 3]:02x}")
  return out


def probe_preamble(progress_cb=None) -> dict:
  """Run the full preamble matrix. Returns:
    {status, panda, eps_bus, identity[], lock{}, services[], variants[], dtc{}, reads[],
     liveness, message}
  status is:
    "security_open"    — a 0x01 seed came back after some preamble (the best outcome);
    "programming_open" — a PROGRAMMING entry was accepted or 0xF186 read 0x02;
    "locked"           — the lock read returned NRC 0x36/0x37, run stopped early;
    "blocked"          — everything refused (the expected case);
    "dropped_out"      — the EPS stopped answering partway; partial data recorded;
    "unreachable" | "failed".
  Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from opendbc.car.isotp import isotp_send
  from opendbc.car.structs import CarParams
  from opendbc.car.uds import UdsClient, SESSION_TYPE, ROUTINE_CONTROL_TYPE, \
    DTC_REPORT_TYPE, DTC_SETTING_TYPE, CONTROL_TYPE, MESSAGE_TYPE, \
    InvalidServiceIdError, MessageTimeoutError, NegativeResponseError
  try:
    from opendbc.car.uds import _negative_response_codes as NRC_TABLE
  except Exception:
    NRC_TABLE = {}

  identity: list = []
  services: list = []
  variants: list = []
  reads: list = []
  result = {
    "status": "failed", "panda": "", "eps_bus": -1, "identity": identity,
    "lock": {}, "services": services, "variants": variants, "dtc": {}, "reads": reads,
    "liveness": "", "message": "",
  }
  steps = [0]

  def nrc(code) -> str:
    return f"NRC 0x{code:02x} {NRC_TABLE.get(code, 'unknown')}"

  def describe(e) -> str:
    if isinstance(e, NegativeResponseError):
      return nrc(e.error_code)
    if isinstance(e, (InvalidServiceIdError, MessageTimeoutError)):
      return f"{type(e).__name__}" + (f": {e}" if str(e) else "")
    return f"{type(e).__name__}" + (f": {e}" if str(e) else "")

  def record(bucket, name, ok, detail) -> None:
    bucket.append({"name": name, "ok": ok, "detail": detail})
    steps[0] += 1
    cb(steps=steps[0], last=name)

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

  # ---- Block A: baseline -----------------------------------------------------------
  eps_bus = None
  for cand in CANDIDATE_BUSES:
    try:
      mk(cand, 0.3).diagnostic_session_control(SESSION_TYPE.DEFAULT)
      eps_bus = cand
      break
    except NegativeResponseError:
      eps_bus = cand   # a negative response still means the EPS is on this bus
      break
    except Exception:
      continue
  result["eps_bus"] = eps_bus if eps_bus is not None else -1
  if eps_bus is None:
    result.update(status="unreachable",
                  message="EPS did not answer on bus 0, 1, or 2. Re-enter Not Ready to Drive "
                          "and re-run.")
    return result

  def extended(u):
    try:
      u.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
      return "accepted"
    except Exception as e:
      return describe(e)

  def to_default():
    try:
      mk(eps_bus, SHORT_TIMEOUT).diagnostic_session_control(SESSION_TYPE.DEFAULT)
    except Exception:
      pass
    time.sleep(0.2)

  def read_did(u, did):
    return bytes(u.read_data_by_identifier(did))

  def read_session(u) -> str:
    try:
      data = read_did(u, ACTIVE_SESSION_DID)
      return f"0x{data[0]:02x}" if data else "empty"
    except Exception as e:
      return describe(e)

  def alive() -> bool:
    try:
      mk(eps_bus, SHORT_TIMEOUT).read_data_by_identifier(ACTIVE_SESSION_DID)
      return True
    except NegativeResponseError:
      return True   # it answered, just refused
    except Exception:
      return False

  u = mk(eps_bus, LONG_TIMEOUT)
  for did, name in ((0xF181, "app_sw_id"), (0xF18C, "ecu_serial")):
    try:
      data = read_did(u, did)
      record(identity, name, True, f"{_ascii(data)} ({data.hex()})")
    except Exception as e:
      record(identity, name, False, describe(e))
  record(identity, "active_session", True, read_session(u))

  try:
    # ---- Block B: lock read ---------------------------------------------------------
    to_default()
    u = mk(eps_bus, LONG_TIMEOUT)
    lock = {"extended": extended(u), "seed_03": "", "seed_01_baseline": "", "locked": False}
    try:
      seed = bytes(u.security_access(SEED_LEVEL_EXT, data_record=SEED_DATA))
      lock["seed_03"] = f"seed {seed.hex()}"
    except NegativeResponseError as e:
      lock["seed_03"] = nrc(e.error_code)
      if e.error_code in (0x36, 0x37):
        lock["locked"] = True
    except Exception as e:
      lock["seed_03"] = describe(e)
    steps[0] += 1
    cb(steps=steps[0], last="lock read")

    if lock["locked"]:
      result.update(status="locked", lock=lock,
                    message=("EPS security is locked out (" + lock["seed_03"] + "). The 15:16 "
                             "send-key attempt left a lock that survived. Power-cycle, re-enter "
                             "Not Ready to Drive, wait a few minutes, and re-run this page — the "
                             "rest of the probe was skipped. Screenshot and send to Calvin."))
      return result

    try:
      seed = bytes(u.security_access(SEED_LEVEL_WILLEM, data_record=SEED_DATA))
      lock["seed_01_baseline"] = f"seed {seed.hex()}"
    except Exception as e:
      lock["seed_01_baseline"] = describe(e)
    result["lock"] = lock
    steps[0] += 1
    cb(steps=steps[0], last="0x01 baseline")

    # ---- Block C: exploit-surface refusal codes -------------------------------------
    to_default()
    u = mk(eps_bus, LONG_TIMEOUT)
    record(services, "extended", True, extended(u))

    for did, name in EXPLOIT_DIDS:
      try:
        data = read_did(u, did)
        record(services, f"read DID 0x{did:03x} ({name})", True, data.hex())
      except Exception as e:
        record(services, f"read DID 0x{did:03x} ({name})", False, describe(e))

    try:
      data = bytes(u.routine_control(ROUTINE_CONTROL_TYPE.REQUEST_RESULTS, VERIFY_ROUTINE))
      record(services, f"routine results 0x{VERIFY_ROUTINE:04x}", True, data.hex() or "empty")
    except Exception as e:
      record(services, f"routine results 0x{VERIFY_ROUTINE:04x}", False, describe(e))

    download_open = False
    try:
      data = bytes(u.request_download(PAYLOAD_RAM_ADDR, PAYLOAD_RAM_SIZE))
      download_open = True
      record(services, "request download (RAM)", True, f"ACCEPTED {data.hex()}")
      try:
        u.request_transfer_exit()
        record(services, "transfer exit (cleanup)", True, "accepted")
      except Exception as e:
        record(services, "transfer exit (cleanup)", False, describe(e))
    except Exception as e:
      record(services, "request download (RAM)", False, describe(e))

    try:
      u.control_dtc_setting(DTC_SETTING_TYPE.OFF)
      record(services, "0x85 DTC setting OFF", True, "accepted")
    except Exception as e:
      record(services, "0x85 DTC setting OFF", False, describe(e))

    try:
      u.communication_control(CONTROL_TYPE.ENABLE_RX_DISABLE_TX, MESSAGE_TYPE.NORMAL)
      record(services, "0x28 comm control disable-tx", True, "accepted")
    except Exception as e:
      record(services, "0x28 comm control disable-tx", False, describe(e))

    dtc_before: list = []
    try:
      data = bytes(u.read_dtc_information(DTC_REPORT_TYPE.DTC_BY_STATUS_MASK))
      dtc_before = _parse_dtcs(data)
      record(services, "DTC snapshot (before)", True, f"{len(dtc_before)} codes")
    except Exception as e:
      record(services, "DTC snapshot (before)", False, describe(e))

    if not alive():
      result.update(status="dropped_out", dtc={"before": dtc_before, "after": [], "new": []},
                    message="The EPS stopped answering after the service probes — the preamble "
                            "variants did not run. Power-cycle, re-enter Not Ready to Drive, and "
                            "re-run. Screenshot and send to Calvin.")
      return result

    # ---- Block D: preamble variants -------------------------------------------------
    def run_variant(name, body, timeout=LONG_TIMEOUT):
      """body(u) sends the preamble + the programming request. Records the session read
      and the 0x01 retry either way."""
      to_default()
      v = {"name": name, "steps": [], "programming": "", "session_after": "",
           "seed_01_after": "", "opened": False}
      uu = mk(eps_bus, timeout)
      v["steps"].append({"step": "extended", "detail": extended(uu)})
      try:
        v["programming"] = body(uu, v)
      except Exception as e:
        v["programming"] = describe(e)
      v["session_after"] = read_session(mk(eps_bus, LONG_TIMEOUT))
      try:
        seed = bytes(mk(eps_bus, LONG_TIMEOUT).security_access(SEED_LEVEL_WILLEM,
                                                               data_record=SEED_DATA))
        v["seed_01_after"] = f"seed {seed.hex()}"
        v["opened"] = True
      except Exception as e:
        v["seed_01_after"] = describe(e)
      variants.append(v)
      steps[0] += 1
      cb(steps=steps[0], last=name)
      return v

    def dtc_off(uu, v):
      try:
        uu.control_dtc_setting(DTC_SETTING_TYPE.OFF)
        v["steps"].append({"step": "0x85 DTC off", "detail": "accepted"})
      except Exception as e:
        v["steps"].append({"step": "0x85 DTC off", "detail": describe(e)})

    def comm_off(uu, v):
      try:
        uu.communication_control(CONTROL_TYPE.ENABLE_RX_DISABLE_TX, MESSAGE_TYPE.NORMAL)
        v["steps"].append({"step": "0x28 disable tx", "detail": "accepted"})
      except Exception as e:
        v["steps"].append({"step": "0x28 disable tx", "detail": describe(e)})

    def programming(uu):
      uu.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
      return "ACCEPTED"

    def v_dtc_only(uu, v):
      dtc_off(uu, v)
      return programming(uu)

    def v_dtc_comm(uu, v):
      dtc_off(uu, v)
      comm_off(uu, v)
      return programming(uu)

    def v_patient(uu, v):
      dtc_off(uu, v)
      comm_off(uu, v)
      time.sleep(1.0)
      return programming(uu)

    def v_suppress(uu, v):
      dtc_off(uu, v)
      comm_off(uu, v)
      isotp_send(panda, PROGRAMMING_SUPPRESS, ADDR, bus=eps_bus)
      v["steps"].append({"step": "raw 10 82 (suppressPosRsp)", "detail": "sent, no response expected"})
      time.sleep(0.5)
      return "sent (suppressed) — see session read"

    def v_functional(uu, v):
      dtc_off(uu, v)
      try:
        isotp_send(panda, COMM_CONTROL_DISABLE_TX, FUNCTIONAL_ADDR, bus=eps_bus)
        v["steps"].append({"step": "functional 0x28 -> 0x7df", "detail": "sent"})
      except Exception as e:
        v["steps"].append({"step": "functional 0x28 -> 0x7df", "detail": describe(e)})
      time.sleep(0.5)
      return programming(uu)

    for name, body, tmo in (
      ("0x85 -> programming", v_dtc_only, LONG_TIMEOUT),
      ("0x85 + 0x28 -> programming", v_dtc_comm, LONG_TIMEOUT),
      ("0x85 + 0x28 -> programming (6s)", v_patient, PATIENT_TIMEOUT),
      ("0x85 + 0x28 -> 10 82 suppressed", v_suppress, LONG_TIMEOUT),
      ("functional 0x28 -> programming", v_functional, LONG_TIMEOUT),
    ):
      if not alive():
        result["liveness"] = f"EPS stopped answering before '{name}'"
        break
      run_variant(name, body, tmo)

    # ---- Block E: DTC diff ----------------------------------------------------------
    dtc_after: list = []
    try:
      data = bytes(mk(eps_bus, LONG_TIMEOUT).read_dtc_information(DTC_REPORT_TYPE.DTC_BY_STATUS_MASK))
      dtc_after = _parse_dtcs(data)
    except Exception:
      pass
    new_dtcs = [d for d in dtc_after if d not in dtc_before]
    result["dtc"] = {"before": dtc_before, "after": dtc_after, "new": new_dtcs}
    steps[0] += 1
    cb(steps=steps[0], last="DTC diff")

    # ---- Block F: reads + liveness --------------------------------------------------
    ur = mk(eps_bus, LONG_TIMEOUT)
    extended(ur)
    for name, addr in READ_TARGETS:
      try:
        data = bytes(ur.read_memory_by_address(addr, 0x10))
        record(reads, f"{name} 0x{addr:08x}", True, data.hex())
      except Exception as e:
        record(reads, f"{name} 0x{addr:08x}", False, describe(e))

    if not result["liveness"]:
      result["liveness"] = "EPS still answering at end of run" if alive() else \
                           "EPS stopped answering at end of run"

  except Exception as e:
    result.update(status="failed", message=f"Probe aborted: {type(e).__name__}: {e}")
    return result

  finally:
    # Restore whatever the preamble changed. A power cycle restores it independently.
    try:
      uc = mk(eps_bus, SHORT_TIMEOUT)
      try:
        uc.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
      except Exception:
        pass
      try:
        uc.communication_control(CONTROL_TYPE.ENABLE_RX_ENABLE_TX, MESSAGE_TYPE.NORMAL)
      except Exception:
        pass
      try:
        uc.control_dtc_setting(DTC_SETTING_TYPE.ON)
      except Exception:
        pass
    except Exception:
      pass
    to_default()

  # ---- classify --------------------------------------------------------------------
  opened = [v for v in variants if v.get("opened")]
  entered = [v for v in variants if v.get("programming") == "ACCEPTED"
             or v.get("session_after") == "0x02"]

  if opened:
    names = ", ".join(v["name"] for v in opened)
    result.update(status="security_open",
                  message=("SECURITY LEVEL 0x01 OPENED after: " + names + ". This is the level "
                           "Willem's Sienna secret belongs to — it is now testable directly. "
                           "Screenshot everything and send to Calvin before running anything "
                           "else."))
  elif entered:
    names = ", ".join(v["name"] for v in entered)
    result.update(status="programming_open",
                  message=("PROGRAMMING SESSION ENTERED via: " + names + ". The pre-programming "
                           "preamble is what the EPS was waiting for. Screenshot everything and "
                           "send to Calvin before running anything else."))
  else:
    detail = f"{len(result['dtc'].get('new', []))} new DTC(s)" if result.get("dtc") else "no DTC data"
    result.update(status="blocked",
                  message=("Programming still refused with the pre-programming preamble "
                           f"({detail}). Level 0x01 stayed shut. Screenshot and send to Calvin — "
                           "the DTC diff and the service refusal codes are the useful part of "
                           "this run even though programming did not open."))
  return result
