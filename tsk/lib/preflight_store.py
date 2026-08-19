#!/usr/bin/env python3
"""Persistent state behind preflight: the security-access log, the measured route,
and the saved reports.

Split out of preflight.py to keep the import graph acyclic. extractor.py,
dump_dataflash.py and dump_range.py all need the unlock gate and the route, and
preflight.py needs to call dump_range.dump(), so the gate cannot live in the module
that imports the dumpers. Nothing here imports a dumper or touches a panda; it reads
and writes JSON under CACHE_DIR and is fully testable off-device.

THE SECURITY-ACCESS LOG RECORDS EVERY UNLOCK ATTEMPT, ACCEPTED OR REJECTED, and
blocks on almost none of them. See is_unlock_blocked() for exactly which two codes
gate and why the rest do not.
"""
import json
import os
import threading
import time
from pathlib import Path

from tsk.lib.env import PREFLIGHT_DIR, PREFLIGHT_ROUTE_PATH, SECURITY_ACCESS_LOG_PATH

# Key for a car whose ECU serial (DID 0xF18C) did not answer. Deliberately not the
# panda's get_serial(): panda/python/__init__.py:620-622 documents that as the
# comma-issued dongle id, so it names the comma and would pool attempts across every
# car that device ever touches, letting a comma arrive at a fresh car already blocked.
UNATTRIBUTED = "unattributed"

# The ECU's own verdict on a key it received and judged. uds.py:283-284.
NRC_INVALID_KEY = 0x35
NRC_EXCEED_ATTEMPTS = 0x36
BLOCKING_ERROR_CODES = (NRC_INVALID_KEY, NRC_EXCEED_ATTEMPTS)

# Route used when preflight has never run, or when it ran against a different panda
# or a different harness state. Reproduces the pre-preflight behaviour exactly:
# logical bus 0, elm327 safety param 0.
DEFAULT_ROUTE = (0, 0)

_lock = threading.Lock()


def _now() -> str:
  return time.strftime("%Y-%m-%dT%H:%M:%S")


def _read_json(path: str, fallback):
  try:
    with open(path, encoding="utf-8") as f:
      data = json.load(f)
  except (OSError, ValueError):
    return fallback
  return data if isinstance(data, dict) else fallback


def _write_json(path: str, payload: dict) -> bool:
  """Atomic replace, so a power cut mid-write cannot leave a truncated log behind."""
  target = Path(path)
  try:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".tmp_{target.name}_{os.getpid()}")
    with open(tmp, "w", encoding="utf-8") as f:
      json.dump(payload, f, indent=2, sort_keys=True)
      f.flush()
      os.fsync(f.fileno())
    os.replace(tmp, target)
  except OSError:
    return False
  return True


# --- Security access log ---


def read_security_access_log() -> dict:
  log = _read_json(SECURITY_ACCESS_LOG_PATH, {})
  ecus = log.get("ecus")
  if not isinstance(ecus, dict):
    return {"version": 1, "ecus": {}}
  return {"version": log.get("version", 1), "ecus": ecus}


def _attempts_for(ecu_serial: str) -> list:
  entry = read_security_access_log()["ecus"].get(ecu_serial or UNATTRIBUTED)
  if not isinstance(entry, dict):
    return []
  attempts = entry.get("attempts")
  return attempts if isinstance(attempts, list) else []


def record_security_access_attempt(ecu_serial, outcome, call, caller,
                                   service_id=None, error_code=None,
                                   exception=None) -> dict:
  """Append one attempt. Returns the recorded entry.

  outcome: accepted | rejected | error
  call:    request_seed | send_key   (which of the two security calls raised)
  caller:  who sent it, e.g. "dump_range:dataflash", "preflight", "extractor"
  """
  key = ecu_serial or UNATTRIBUTED
  entry = {
    "time": _now(),
    "outcome": outcome,
    "call": call,
    "caller": caller,
    "service_id": service_id,
    "error_code": error_code,
    "exception": exception,
  }
  with _lock:
    log = read_security_access_log()
    ecus = log["ecus"]
    if not isinstance(ecus.get(key), dict):
      ecus[key] = {"attempts": []}
    if not isinstance(ecus[key].get("attempts"), list):
      ecus[key]["attempts"] = []
    ecus[key]["attempts"].append(entry)
    _write_json(SECURITY_ACCESS_LOG_PATH, log)
  return entry


def classify_security_exception(exc):
  """(outcome, service_id, error_code, exception_name) for a security_access raise.

  Classifies on the exception's class name rather than the class object so this
  module keeps no opendbc import; the five types security_access() can raise are
  listed at the call site in extractor.security_access_with_log().
  """
  name = type(exc).__name__
  if name == "NegativeResponseError":
    return ("rejected", getattr(exc, "service_id", None),
            getattr(exc, "error_code", None), name)
  return "error", None, None, name


def has_unlocked(ecu_serial) -> bool:
  return any(a.get("outcome") == "accepted" for a in _attempts_for(ecu_serial))


def is_unlock_blocked(ecu_serial) -> bool:
  """True when this ECU should not be sent another key.

  Blocked when the serial has NO accepted attempt and carries a
  NegativeResponseError from the SEND_KEY call with error_code 0x35 or 0x36. Those
  two are the ECU's own verdict on a key it received and judged, and a second bad
  key is what advances a failure counter nobody has characterised on an unknown car.

  Everything else is recorded and blocks nothing:
    - any failure of the REQUEST_SEED call, since no key was sent;
    - any timeout or invalid-response error, since nothing came back to attribute.
      A timeout is silence, covering both "the key never reached the ECU" and "it
      arrived and the answer was lost". If a timeout did hide a delivered bad key
      the ECU's counter is armed and the NEXT attempt returns 0x35 or 0x36, which
      blocks. Blocking on silence instead turns a documented routine event, the EPS
      dropping out under load, into a dead end on a car's first press;
    - any other error_code, including 0x37 "required time delay not expired"
      (uds.py:285), which names a wait, and whose preceding 0x36 already blocks.

  ONCE ANY ATTEMPT ON A SERIAL IS ACCEPTED, NOTHING GATES FROM ANY PATH (Calvin,
  2026-08-19: the car is known to work, so later failures are glitches owners
  retry). A block therefore exists only before the first success, which is a state
  in which no dump can have run, so Delete Dumps clears it at no cost to the owner
  and no separate reset action is needed.
  """
  attempts = _attempts_for(ecu_serial)
  if any(a.get("outcome") == "accepted" for a in attempts):
    return False
  for a in attempts:
    if a.get("call") != "send_key":
      continue
    if a.get("exception") != "NegativeResponseError":
      continue
    if a.get("error_code") in BLOCKING_ERROR_CODES:
      return True
  return False


def block_reason(ecu_serial) -> str:
  """One line naming why this ECU is blocked, or "" when it is not."""
  if not is_unlock_blocked(ecu_serial):
    return ""
  codes = sorted({a.get("error_code") for a in _attempts_for(ecu_serial)
                  if a.get("call") == "send_key"
                  and a.get("error_code") in BLOCKING_ERROR_CODES})
  shown = ", ".join(f"0x{c:02x}" for c in codes)
  return (f"This ECU rejected a security key ({shown}) and has never accepted one.\n"
          "No further key will be sent to it. Delete Dumps clears this.")


# --- Measured route ---


def save_route(bus, param, panda_serial=None, harness_status=None, ecu_serial=None,
               stamp=None) -> bool:
  """Persist the (bus, param) pair the probe measured, with what it was measured on.

  NOTHING HERE RECORDS A PIN STATE. "Swapped" means the CAN conductors differ from
  that car's factory pinout, and a tool with no model knowledge has no factory pinout
  to compare against, so there is nothing to store that is not a guess. A repin shows
  up as a different answering pair, which the sweep records as a measurement.
  """
  payload = {
    "bus": int(bus),
    "param": int(param),
    "panda_serial": panda_serial,
    "harness_status": harness_status,
    "ecu_serial": ecu_serial,
    "stamp": stamp or _now(),
  }
  with _lock:
    return _write_json(PREFLIGHT_ROUTE_PATH, payload)


def load_route():
  route = _read_json(PREFLIGHT_ROUTE_PATH, {})
  if "bus" not in route or "param" not in route:
    return None
  return route


def stored_ecu_serial() -> str:
  """The ECU serial the last preflight read, or UNATTRIBUTED. Unvalidated: prefer
  identity_for(), which discards it when the panda is not the one it was read on."""
  route = load_route() or {}
  return route.get("ecu_serial") or UNATTRIBUTED


def _route_matches(route, panda_serial, harness_status) -> bool:
  """Whether a stored route was measured on this panda in this harness orientation.

  panda/board/boards/red.h:28-67 selects the FDCAN2 pin pair on the exclusive-or of
  the safety param and the harness flip, so the same param reaches different
  conductors once the harness flips: a route measured under one orientation is not a
  route under the other.
  """
  if route is None:
    return False
  if panda_serial is not None and route.get("panda_serial") not in (None, panda_serial):
    return False
  if harness_status is not None and route.get("harness_status") not in (None, harness_status):
    return False
  return True


def route_for(panda_serial=None, harness_status=None):
  """(bus, param) to use, falling back to DEFAULT_ROUTE."""
  route = load_route()
  if not _route_matches(route, panda_serial, harness_status):
    return DEFAULT_ROUTE
  try:
    return int(route["bus"]), int(route["param"])
  except (KeyError, TypeError, ValueError):
    return DEFAULT_ROUTE


def identity_for(panda_serial=None, harness_status=None):
  """(bus, param, ecu_serial) for this panda, all three falling back together.

  The dumpers key their log entries on the serial preflight read rather than reading
  DID 0xF18C themselves: the production path is proven at its current UDS traffic,
  and adding a read between the session ladder and the security call risks a late
  response being picked up by the request that follows it. Discarding the serial
  alongside the route closes the case where a comma is moved to a different car
  carrying a different panda; it does NOT close the case where the same comma is
  moved to a second car without re-running preflight, which still attributes that
  car's attempts to the first one.
  """
  route = load_route()
  if not _route_matches(route, panda_serial, harness_status):
    return DEFAULT_ROUTE[0], DEFAULT_ROUTE[1], UNATTRIBUTED
  bus, param = route_for(panda_serial, harness_status)
  return bus, param, route.get("ecu_serial") or UNATTRIBUTED


def has_run() -> bool:
  """True once a preflight has stored a route on this device.

  NOT the gate on the dump rows. A route is stored before the exploit and even when no
  route opened PROGRAMMING, so this says a preflight reached the ECU, never that it
  passed. The UI gates on the report's result line.
  """
  return load_route() is not None


# --- Reports ---


def report_dir() -> Path:
  return Path(PREFLIGHT_DIR)


def report_path(ecu_serial, stamp) -> Path:
  safe = "".join(c for c in (ecu_serial or UNATTRIBUTED) if c.isalnum() or c in "-_")
  return report_dir() / f"preflight_{safe or UNATTRIBUTED}_{stamp}.json"


def save_report(report: dict) -> str:
  path = report_path(report.get("ecu_serial"), report.get("stamp", "unknown"))
  if _write_json(str(path), report):
    return str(path)
  return ""


# datetime.now().strftime("%Y%m%d-%H%M%S") is always 15 characters and never carries
# an underscore, which is what makes the right-split below stable.
STAMP_LENGTH = 15


def report_stamp(name: str) -> str:
  """The stamp out of a report filename, or "" when the name has no usable one.

  RIGHT-split, deliberately: report_path() sanitises the serial with
  `c.isalnum() or c in "-_"`, so an underscore inside a serial survives into the
  middle field and a left-split would return part of the serial. The stamp is the
  last field and has no underscore of its own.
  """
  stem = name[:-len(".json")] if name.endswith(".json") else name
  stamp = stem.rsplit("_", 1)[-1]
  return stamp if len(stamp) == STAMP_LENGTH else ""


def list_reports() -> list:
  """Report filenames, newest first.

  ORDERED ON THE STAMP RATHER THAN THE WHOLE FILENAME. The serial sits ahead of the
  stamp in `preflight_<serial>_<stamp>.json`, so a plain filename sort orders by
  serial: `preflight_unattributed_*` leads with `u` (117) while a Toyota serial leads
  with `8` (56), and once one unattributed report existed it stayed "latest" forever,
  which fed an older failed run into rehydrate_preflight_state() after every restart.

  A name with no parseable stamp sorts last instead of raising, which covers the
  `"unknown"` stamp save_report() writes for a report that has none.
  """
  try:
    names = [p.name for p in report_dir().iterdir()
             if p.name.startswith("preflight_") and p.suffix == ".json"]
  except OSError:
    return []
  names.sort(key=lambda n: (report_stamp(n), n), reverse=True)
  return names


def latest_report():
  names = list_reports()
  if not names:
    return None
  data = _read_json(str(report_dir() / names[0]), {})
  return data or None
