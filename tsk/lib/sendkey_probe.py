#!/usr/bin/env python3
"""Send-key test at security level 0x03/0x04 using the Willem secret.

The Corolla EPS (8965F1208000) returns a level-0x03 seed in the extended session. This
sends the level-0x04 key computed with Willem's Sienna secret to answer one question:
does the Corolla share the Sienna's seed->key secret?

  accepted  -> yes; security opens in extended with no programming session. The probe then
               retries the 0x23 read at the key region / dataflash base to see whether the
               read range opens once security is passed.
  NRC 0x35  -> no (invalid key); the Corolla uses a different secret and the firmware-dump
               path is needed to recover it.
  NRC 0x36/0x37 -> the EPS locked security out (too many attempts / time delay) — power-
               cycle before retrying.

The key math is Willem's, byte-for-byte the same as extractor.hack():
  derived  = AES-ECB-decrypt(SECRET, 16 zero bytes)
  response = AES-ECB-encrypt(derived, seed)

ONE key is sent per run — a wrong key can increment the EPS lockout counter, so the page
is tap-to-run (not auto-run) and warns to run it once. The EPS bus is found by the same
software sweep the other tools use (no pin swap). is_agnos-gated; server mocks it off-device.
"""
import time

from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.dump_dataflash import ADDR, DUMP_START, KNOWN_KEY_OFFSET
from tsk.lib.dump_diag import CANDIDATE_BUSES

LONG_TIMEOUT = 3.0
SEED_LEVEL = 0x03    # REQUEST_SEED sub-function (odd)
KEY_LEVEL = 0x04     # SEND_KEY sub-function (even) for the same 0x03/0x04 pair
SEED_DATA = b"\x00" * 16

# Post-unlock read targets: the Sienna key region and the dataflash base. These are the
# Sienna addresses (out-of-range for the Corolla before security); the point is to see
# whether passing security widens what 0x23 will read.
KEY_REGION = DUMP_START + KNOWN_KEY_OFFSET   # 0xFF206E14
READ_TARGETS = [("key region", KEY_REGION), ("dataflash base", DUMP_START)]


def _noop(**kwargs) -> None:
  pass


def send_willem_key(progress_cb=None) -> dict:
  """Request the 0x03 seed, compute the Willem key, send it at 0x04. Returns:
    {status, panda, eps_bus, session, seed, key, send_key, post_unlock_reads[], message}
  status is:
    "unlocked"    — the key was accepted; security is open in extended;
    "invalid_key" — NRC 0x35, the secret differs;
    "locked"      — NRC 0x36/0x37, security locked out;
    "denied"      — NRC 0x33;
    "rejected"    — some other NRC (e.g. 0x22/0x24) — reported, no secret claim;
    "no_seed"     — the seed request itself was refused;
    "unreachable" | "failed".
  Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from Crypto.Cipher import AES
  from opendbc.car.structs import CarParams
  from opendbc.car.uds import UdsClient, SESSION_TYPE, \
    InvalidServiceIdError, MessageTimeoutError, NegativeResponseError
  try:
    from opendbc.car.uds import _negative_response_codes as NRC_TABLE
  except Exception:
    NRC_TABLE = {}

  reads: list = []
  result = {
    "status": "failed", "panda": "", "eps_bus": -1, "session": "", "seed": "",
    "key": "", "send_key": "", "post_unlock_reads": reads, "message": "",
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

  # Software bus sweep.
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

  u = mk(eps_bus, LONG_TIMEOUT)

  # Enter EXTENDED (where the 0x03 seed is available).
  try:
    u.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    result["session"] = "extended"
  except NegativeResponseError as e:
    result["session"] = nrc(e.error_code)
  except Exception as e:
    result["session"] = type(e).__name__
  cb(step="extended", last="extended session")

  # Request the 0x03 seed.
  try:
    seed = bytes(u.security_access(SEED_LEVEL, data_record=SEED_DATA))
    result["seed"] = seed.hex()
  except NegativeResponseError as e:
    result.update(status="no_seed", message=f"Seed request at 0x03 refused: {nrc(e.error_code)}. "
                  "Re-enter Not Ready to Drive and re-run. Screenshot and send to Calvin.")
    return result
  except Exception as e:
    result.update(status="no_seed", message=f"Seed request at 0x03 failed: {type(e).__name__}. "
                  "Re-enter Not Ready to Drive and re-run. Screenshot and send to Calvin.")
    return result
  cb(step="seed", last=f"seed {result['seed'][:16]}")

  if len(seed) != 16:
    result.update(status="failed",
                  message=f"Seed is {len(seed)} bytes, expected 16 — can't compute the AES key. "
                  "Screenshot and send to Calvin.")
    return result

  # Willem seed->key (identical to extractor.hack()).
  try:
    derived = AES.new(TSKExtractor.SEED_KEY_SECRET, AES.MODE_ECB).decrypt(SEED_DATA)
    response = AES.new(derived, AES.MODE_ECB).encrypt(seed)
    result["key"] = response.hex()
  except Exception as e:
    result.update(status="failed", message=f"Key computation failed: {type(e).__name__}.")
    return result
  cb(step="key", last="computed Willem key")

  # Send the key ONCE.
  try:
    u.security_access(KEY_LEVEL, security_key=response)
    result["send_key"] = "accepted"
    result["status"] = "unlocked"
  except NegativeResponseError as e:
    result["send_key"] = nrc(e.error_code)
    if e.error_code == 0x35:
      result["status"] = "invalid_key"
    elif e.error_code in (0x36, 0x37):
      result["status"] = "locked"
    elif e.error_code == 0x33:
      result["status"] = "denied"
    else:
      # An NRC that isn't a clean invalid-key / lockout / denial (e.g. 0x22
      # conditionsNotCorrect, 0x24 requestSequenceError). Report it without
      # claiming the secret differs — that would misdirect to the firmware dump.
      result["status"] = "rejected"
  except (InvalidServiceIdError, MessageTimeoutError) as e:
    result["send_key"] = f"{type(e).__name__}" + (f": {e}" if str(e) else "")
    result["status"] = "failed"
  except Exception as e:
    result["send_key"] = type(e).__name__
    result["status"] = "failed"
  cb(step="send_key", last=f"send_key {result['send_key']}")

  # If unlocked, see whether 0x23 opens up now that security passed.
  if result["status"] == "unlocked":
    for name, addr in READ_TARGETS:
      entry = {"name": name, "address": f"0x{addr:08x}", "size": 16}
      try:
        data = bytes(u.read_memory_by_address(addr, 0x10))
        entry.update(ok=True, detail=data.hex())
      except NegativeResponseError as e:
        entry.update(ok=False, detail=nrc(e.error_code))
      except Exception as e:
        entry.update(ok=False, detail=type(e).__name__)
      reads.append(entry)
      cb(step="read", last=name)

  if result["status"] == "unlocked":
    opened = [r for r in reads if r.get("ok")]
    if opened:
      result["message"] = ("Willem key ACCEPTED at level 0x03/0x04 — the Corolla shares the secret, and 0x23 "
                           f"now reads {len(opened)} of {len(reads)} target(s). Screenshot and send to Calvin.")
    else:
      result["message"] = ("Willem key ACCEPTED at level 0x03/0x04 — the Corolla shares the secret. Security is "
                           "open in extended, but 0x23 is still out-of-range at the Sienna addresses (the Corolla "
                           "key is elsewhere). Screenshot and send to Calvin.")
  elif result["status"] == "invalid_key":
    result["message"] = ("Willem key rejected (invalid key) — the Corolla uses a different seed->key secret. The "
                         "firmware-dump path is needed to recover it. Screenshot and send to Calvin.")
  elif result["status"] == "locked":
    result["message"] = ("Security locked out (too many attempts / time delay). Power-cycle the panda / re-enter "
                         "Not Ready to Drive before trying again. Screenshot and send to Calvin.")
  elif result["status"] == "denied":
    result["message"] = ("Send-key denied (NRC 0x33) — security access is not permitted here in this session/state. "
                         "Screenshot and send to Calvin.")
  else:
    result["message"] = (f"Send-key did not complete cleanly: {result['send_key']}. Screenshot and send to Calvin.")
  return result
