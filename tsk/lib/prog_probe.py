#!/usr/bin/env python3
"""Programming-session probe: try several ways to enter the UDS PROGRAMMING session
on an EPS that answers DEFAULT/EXTENDED but times out on PROGRAMMING.

Built for the 2025 Corolla Hybrid (EPS 8965F1208000), which the sweep reached on bus 1
and which grants default/extended sessions but does not answer the programming-session
request. One run tests every plausible software path before anyone touches hardware:

  1-4. entry sequences (patient, double, direct, tester-present), each reset to DEFAULT.
  5.   safety-system session (0x04) — a session we otherwise never try.
  6.   security-level sweep — REQUEST_SEED at 0x01..0x0b, no key sent, so no lockout;
       finds which level (if any) grants a seed in EXTENDED.
  7.   did-it-take — send PROGRAMMING, ignore the timeout, read ACTIVE_DIAGNOSTIC_SESSION
       (0xF186): 0x02 means the EPS switched silently and only the response was lost.
  8.   all-bus-listen — send PROGRAMMING physical + functional (0x7df), then listen on
       every bus for the EPS response arb id (0x7a9). Catches a response rerouted to a
       bus we don't normally read. This is the assuming-no-pin-swap discriminator: if
       the response is on a connected bus, software catches it; if it's dry AND did-it-
       take shows a silent switch, the response is on a wire nothing here is pinned to.
  9.   security-first (LAST) — SEND_KEY with the Willem key, the one write that can trip
       a temporary lockout, so it runs after everything else.

Read intent apart from the single security SEND_KEY. Off-device raises NotAGNOSError.
"""
import time

from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.dump_dataflash import ADDR
from tsk.lib.dump_diag import CANDIDATE_BUSES

LONG_TIMEOUT = 3.0        # patience for an EPS that resets into its bootloader on PROGRAMMING
LISTEN_SECONDS = 2.0      # all-bus listen window after a PROGRAMMING request
FUNCTIONAL_ADDR = 0x7DF   # OBD-II functional/broadcast request address
ACTIVE_SESSION_DID = 0xF186
SECURITY_LEVELS = (0x01, 0x03, 0x05, 0x07, 0x09, 0x0B)   # odd = REQUEST_SEED levels
PROGRAMMING_REQUEST = b"\x10\x02"   # diagnostic_session_control(PROGRAMMING), single frame


def _noop(**kwargs) -> None:
  pass


def probe_programming(progress_cb=None) -> dict:
  """Run the programming-session entry matrix. Returns:
    {status, panda, eps_bus, attempts[], security{}, security_levels[], did_it_take{},
     all_bus[], message}
  status is "entered" (some PROGRAMMING sequence worked) | "blocked" | "unreachable" |
  "failed". Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from Crypto.Cipher import AES
  from opendbc.car.isotp import isotp_send
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
    "security": {}, "security_levels": [], "did_it_take": {}, "all_bus": [], "message": "",
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

  def record(name, ok, detail, programming=True):
    attempts.append({"name": name, "ok": ok, "detail": detail, "programming": programming})
    cb(attempts=len(attempts), last=name)

  def attempt(name, fn, programming=True):
    # Reset to a clean default session, run the sequence, and record how its final
    # session request fared. Never raises.
    reset_default()
    try:
      fn()
      record(name, True, "session accepted", programming)
    except NegativeResponseError as e:
      record(name, False, nrc(e.error_code), programming)
    except (InvalidServiceIdError, MessageTimeoutError) as e:
      record(name, False, f"{type(e).__name__}: {e}" if str(e) else type(e).__name__, programming)
    except Exception as e:
      record(name, False, f"{type(e).__name__}: {e}" if str(e) else type(e).__name__, programming)

  # 1. EXTENDED then PROGRAMMING, patient timeout.
  def seq_patient():
    u = mk(eps_bus, LONG_TIMEOUT)
    u.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    time.sleep(0.7)
    u.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
  attempt("extended -> programming (3s)", seq_patient)

  # 2. Double PROGRAMMING with a 1s settle, mirroring the Sienna production flow.
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

  # 5. Safety-system session (0x04) — informational, not a programming entry, so it does
  # not count toward "entered".
  def seq_safety():
    mk(eps_bus, LONG_TIMEOUT).diagnostic_session_control(SESSION_TYPE.SAFETY_SYSTEM_DIAGNOSTIC)
  attempt("safety-system session (0x04)", seq_safety, programming=False)

  # 6. Security-level sweep — REQUEST_SEED only (no key), so no lockout. The 0x7e we get
  # on level 1 means "seed not available in this session"; a different level may be the
  # one EXTENDED grants.
  levels: list = []
  for lvl in SECURITY_LEVELS:
    reset_default()
    u = mk(eps_bus, LONG_TIMEOUT)
    try:
      u.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except Exception:
      pass
    try:
      seed = u.security_access(lvl, data_record=b"\x00" * 16)
      levels.append({"level": f"0x{lvl:02x}", "detail": f"seed {bytes(seed).hex()}"})
    except NegativeResponseError as e:
      levels.append({"level": f"0x{lvl:02x}", "detail": nrc(e.error_code)})
    except Exception as e:
      levels.append({"level": f"0x{lvl:02x}", "detail": type(e).__name__})
    cb(attempts=len(attempts), last=f"security level {lvl:#04x}")
  result["security_levels"] = levels

  # 7. did-it-take — send PROGRAMMING, ignore the timeout, read the active session. 0x02
  # means it switched silently. Reads can be blocked in programming, so an NRC/timeout
  # here is inconclusive rather than a "no".
  def read_session(u):
    try:
      data = bytes(u.read_data_by_identifier(ACTIVE_SESSION_DID))
      return f"0x{data[0]:02x}" if data else "empty"
    except NegativeResponseError as e:
      return nrc(e.error_code)
    except Exception as e:
      return type(e).__name__

  reset_default()
  u = mk(eps_bus, LONG_TIMEOUT)
  try:
    u.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
  except Exception:
    pass
  before = read_session(u)
  try:
    u.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
  except Exception:
    pass
  after = read_session(u)
  if after == "0x02":
    switched: object = True
  elif after in ("0x01", "0x03", "0x04"):
    switched = False
  else:
    switched = None   # couldn't read the session — inconclusive
  result["did_it_take"] = {"before": before, "after": after, "switched": switched}
  cb(attempts=len(attempts), last="did-it-take")

  # 8. all-bus-listen — send PROGRAMMING physical + functional, then listen on every bus
  # for the EPS response arb id (ADDR+8). A hit on a bus other than eps_bus is a reroute.
  resp_id = ADDR + 8
  seen: dict = {b: set() for b in CANDIDATE_BUSES}
  reset_default()
  for tx in (ADDR, FUNCTIONAL_ADDR):
    try:
      isotp_send(panda, PROGRAMMING_REQUEST, tx, bus=eps_bus)
    except Exception:
      pass
  begin = time.time()
  while time.time() - begin < LISTEN_SECONDS:
    try:
      recv = panda.can_recv()
    except Exception:
      break
    for addr, *_, data, bus in recv:
      seen.setdefault(bus, set()).add(addr)
    time.sleep(0.001)
  all_bus = []
  for bus in sorted(seen):
    ids = sorted(seen[bus])
    all_bus.append({
      "bus": bus,
      "unique": len(ids),
      "saw_eps_response": resp_id in seen[bus],
      "ids": [f"0x{a:x}" for a in ids[:20]],
    })
  result["all_bus"] = all_bus
  cb(attempts=len(attempts), last="all-bus-listen")

  # 9. Security-first (LAST — a failed key can trip a temporary lockout). Capture the
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

  entered = any(a["ok"] for a in attempts if a.get("programming"))
  result["status"] = "entered" if entered else "blocked"
  if entered:
    hit = next(a["name"] for a in attempts if a["ok"] and a.get("programming"))
    result["message"] = f"A programming-session sequence worked: {hit}. The exploit path may be open — tell Calvin."
  elif switched is True:
    result["message"] = (f"No sequence entered on bus {eps_bus}, but the session switched to 0x02 silently — "
                         "the EPS enters programming and the response is being lost. A repin or a scope on "
                         "the harness now has a target; check all-bus-listen for a reroute first.")
  elif switched is False:
    result["message"] = (f"No sequence entered on bus {eps_bus}, and the session stayed put ({after}) — the EPS "
                         "is refusing programming, not rerouting the response. The firmware-dump path is next.")
  else:
    result["message"] = (f"No sequence entered on bus {eps_bus}; the session DID was unreadable so did-it-take "
                         "is inconclusive. Use all-bus-listen (a reroute) as the deciding signal.")
  return result
