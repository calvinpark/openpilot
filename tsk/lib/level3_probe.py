#!/usr/bin/env python3
"""Security level 0x03 isolation probe: does REQUEST_SEED at level 0x03 return a seed
from a clean session, or only as a side effect of prior programming/seed traffic?

The 2025 Corolla (EPS 8965F1208000) handed out a level-0x03 seed during prog_probe's
security sweep — but that sweep first fired five PROGRAMMING entry sequences and a
level-0x01 request, each followed by a best-effort DEFAULT reset that swallows failures.
So we never saw 0x03 answer from a session we know is clean. This probe requests the
0x03 seed as the FIRST security operation after a fresh connect, then adds one primer at
a time (a prior 0x01 request, a prior PROGRAMMING attempt) to see whether any of them is
what makes 0x03 answer.

Seed requests only — no key is ever sent, so there is no lockout risk and it is safe to
re-run. Every session transition is recorded (accepted / NRC / timeout) so a swallowed
reset can't hide. The EPS bus is found by the same software sweep the other tools use
(no pin swap). is_agnos-gated; the server mocks it off-device.
"""
import time

from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.dump_dataflash import ADDR
from tsk.lib.dump_diag import CANDIDATE_BUSES

LONG_TIMEOUT = 3.0        # patience for a slow EPS
SEED_LEVEL = 0x03         # the level that answered in the in-car sweep
SEED_DATA = b"\x00" * 16  # data_record sent with REQUEST_SEED (mirrors the Sienna flow)
PROGRAMMING_REQUEST = b"\x10\x02"


def _noop(**kwargs) -> None:
  pass


def probe_level3(progress_cb=None) -> dict:
  """Run the 0x03-seed isolation matrix. Returns:
    {status, panda, eps_bus, tests[], seeds, primer, message}
  status is:
    "reproduced"  — the clean test (0x03 first, extended only) returned a seed;
    "conditional" — 0x03 answered only after a primer (recorded in `primer`);
    "no_seed"     — 0x03 never returned a seed this run;
    "unreachable" | "failed".
  Each test is {name, steps[{step, detail}], seed, got_seed}. Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from opendbc.car.isotp import isotp_send
  from opendbc.car.structs import CarParams
  from opendbc.car.uds import UdsClient, SESSION_TYPE, \
    InvalidServiceIdError, MessageTimeoutError, NegativeResponseError
  try:
    from opendbc.car.uds import _negative_response_codes as NRC_TABLE
  except Exception:
    NRC_TABLE = {}

  tests: list = []
  result = {
    "status": "failed", "panda": "", "eps_bus": -1, "tests": tests,
    "seeds": [], "primer": "", "message": "",
  }

  def nrc(code) -> str:
    return f"NRC 0x{code:02x} {NRC_TABLE.get(code, 'unknown')}"

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

  # Software bus sweep: first candidate that answers a default-session request.
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

  def enter(u, session):
    try:
      u.diagnostic_session_control(session)
      return "accepted"
    except NegativeResponseError as e:
      return nrc(e.error_code)
    except (InvalidServiceIdError, MessageTimeoutError) as e:
      return f"{type(e).__name__}" + (f": {e}" if str(e) else "")
    except Exception as e:
      return type(e).__name__

  def request_seed(u, level):
    """Returns (detail_str, got_seed, seed_hex)."""
    try:
      seed = u.security_access(level, data_record=SEED_DATA)
      hexs = bytes(seed).hex()
      return f"seed {hexs}", True, hexs
    except NegativeResponseError as e:
      return nrc(e.error_code), False, ""
    except Exception as e:
      return type(e).__name__, False, ""

  seeds: list = []

  def run_test(name, steps):
    """steps: list of ("step name", callable(u)->detail). The callable may set a
    'seed' via the shared closure below. Records the test and its seed."""
    entry = {"name": name, "steps": [], "seed": "", "got_seed": False}
    u = mk(eps_bus, LONG_TIMEOUT)
    got_seed = False
    seed_hex = ""
    for step_name, fn in steps:
      detail, is_seed, hx = fn(u)
      entry["steps"].append({"step": step_name, "detail": detail})
      if is_seed:
        got_seed = True
        seed_hex = hx
        seeds.append(hx)
    entry["seed"] = seed_hex
    entry["got_seed"] = got_seed
    tests.append(entry)
    cb(tests=len(tests), last=name)
    return got_seed

  # A DEFAULT reset that reports whether it took, so a swallowed reset can't hide.
  def reset_step(u):
    return enter(u, SESSION_TYPE.DEFAULT), False, ""

  def extended_step(u):
    return enter(u, SESSION_TYPE.EXTENDED_DIAGNOSTIC), False, ""

  def seed03_step(u):
    return request_seed(u, SEED_LEVEL)

  def seed01_step(u):
    return request_seed(u, 0x01)

  def poke_programming_step(u):
    # Fire-and-forget PROGRAMMING (never waits, never switches this client). If a prior
    # programming attempt is what unlocks 0x03, this reproduces it.
    try:
      isotp_send(panda, PROGRAMMING_REQUEST, ADDR, bus=eps_bus)
    except Exception:
      pass
    time.sleep(0.3)
    return "sent 10 02 (ignored response)", False, ""

  # Test 1 — clean: DEFAULT -> EXTENDED -> seed 0x03 (first security op), read twice.
  clean_ok = run_test("clean extended (0x03 first)", [
    ("default", reset_step),
    ("extended", extended_step),
    ("seed 0x03", seed03_step),
    ("seed 0x03 again", seed03_step),
  ])

  # Test 2 — default session only: does 0x03 need EXTENDED at all?
  run_test("default session (no extended)", [
    ("default", reset_step),
    ("seed 0x03", seed03_step),
  ])

  # Test 3 — primer = a prior 0x01 seed request.
  after_01 = run_test("0x01 first, then 0x03", [
    ("default", reset_step),
    ("extended", extended_step),
    ("seed 0x01", seed01_step),
    ("seed 0x03", seed03_step),
  ])

  # Test 4 — primer = a prior PROGRAMMING attempt.
  after_prog = run_test("programming poke, then 0x03", [
    ("default", reset_step),
    ("extended", extended_step),
    ("poke programming", poke_programming_step),
    ("seed 0x03", seed03_step),
  ])

  result["seeds"] = seeds

  if clean_ok:
    result["status"] = "reproduced"
    distinct = len(set(seeds))
    note = "seeds differ each request" if distinct > 1 else "same seed returned each request"
    result["message"] = (f"Level 0x03 returned a seed from a clean extended session on bus {eps_bus} "
                         f"({note}) — it is its own input/output, not a side effect of prior traffic. "
                         "Screenshot and send to Calvin.")
  elif after_01 or after_prog:
    result["status"] = "conditional"
    primer = "a prior 0x01 seed request" if after_01 else "a prior PROGRAMMING attempt"
    result["primer"] = "0x01" if after_01 else "programming"
    result["message"] = (f"Level 0x03 answered only after {primer}, not from a clean session — the earlier "
                         "seed depended on prior traffic. Screenshot and send to Calvin.")
  else:
    result["status"] = "no_seed"
    result["message"] = (f"Level 0x03 returned no seed on bus {eps_bus} in any variant this run. The EPS may "
                         "have dropped out of the diagnostic state — re-enter Not Ready to Drive / power-cycle "
                         "the panda and re-run. Screenshot and send to Calvin.")
  return result
