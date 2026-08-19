#!/usr/bin/env python3
"""Preflight: one press that probes the car, runs the exploit once, and reports.

WHY. Every failure on an unknown car currently produces the same thing, an empty dump
or a timeout, with no way for the owner to tell which cause they hit. Running the
chain in order and printing a report makes each cause a distinguishable line, and the
report is the artifact owners send Calvin.

SCOPE (Calvin, 2026-08-19): PREFLIGHT RUNS THE EXPLOIT AND DUMPS, AND ANALYSES NO
DUMPED BYTE. Content gets examined offline from the downloaded files. Nothing here
reads a value out of a dump, and the only memory addresses in this module are the ones
the dump itself needs, which live in dump_range.PROFILES.

Steps, each recording ok / an NRC / silent, so a run that dies partway ships
everything above it and steps that never ran print `not attempted`:

  1. Panda: dongle id, firmware version, car_harness_status.
  2. Bus sweep: a DEFAULT session at 0x7a1 on buses 0, 1 and 2 under BOTH elm327
     param 0 and param 1, recording which answered under each.
  3. Identity: 0xF181, 0xF18C, 0xF186. Free reads, no security, no state change. Ahead
     of the probe, so the part number and the serial survive a run that ends there.
  4. Traffic: per-bus frame counts, distinct arbitration IDs, 0x0F sync counts.
     Reported only; a zero sync count never gates the outcome, since albinoelephant's
     1,232 sync rows sit on buses 0 and 2 with zero on bus 1.
  5. Route probe: on every pair the sweep found answering, the session ladder plus the
     four services that came back silent on the 07-25 Corolla sweep. See _probe_route.
  6. The exploit run: ONE call to dump_range.dump() on the existing `dataflash`
     profile, on the route whose probe opened PROGRAMMING. That single call performs
     the session ladder, one REQUEST_SEED, one SEND_KEY, the upload, the trigger and
     the collect, so one press sends at most one unlock. Zero frames fails, any frames
     passes, and a gapped read never moves the outcome. When no route opened
     PROGRAMMING the step is skipped: no route could have run it, and skipping sends
     no key and hands the car back sooner.

A separate security stage followed by a dump that repeats the whole flow would send
two keys while reporting one; collapsing them is what keeps the count truthful. The
report still prints DEFAULT, EXTENDED, PROGRAMMING, seed, unlock and dump as separate
lines, because dump_range splits its session except per transition and reports each
through stage_cb. Same sequence, same sleeps; only exception granularity changed.

THE ROUTE IS MEASURED, NEVER MAPPED. "Stock" does not name a bus: it is bus 0 on a
Sienna, bus 1 on a stock Corolla through OBD, and bus 0 again on a repinned Corolla.
Nothing here asks the owner about wiring, and nothing infers it from a part number: a
repinned car shows up as a different answering pair, which the sweep already records.

AND THE ROUTE IS PICKED BY THE ONE STEP THAT DISCRIMINATES. Span's Corolla answered a
DEFAULT session on bus 1 under both params on 2026-08-19, and the earlier array-order
pick sent the exploit down param 0, the OBD-II multiplexed path, which is the path the
2026-08-11 finding says confounds every silent result. A DEFAULT session answers on
any route that reaches the ECU at all; PROGRAMMING is the transition that has ever
told two paths apart on that car, so PROGRAMMING is what chooses.
"""
import subprocess
import time
from datetime import datetime

from tsk.lib import preflight_store
from tsk.lib.dump_range import dump as dump_range, PROFILES
from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, RetryError, TSKExtractor

ADDR = TSKExtractor.ADDR  # 0x7a1
SWEEP_BUSES = (0, 1, 2)
SWEEP_PARAMS = (0, 1)

# The profile the exploit step runs. Already pinned, already run on the Sienna and on
# albinoelephant's Corolla, so a null from it is evidence about the part.
EXPLOIT_PROFILE = "dataflash"

# Read-only bus sample. Long enough to see the periodic traffic on a live bus,
# short enough that a preflight stays a single press.
TRAFFIC_SECONDS = 3.0

SYNC_ADDR = 0x0F

NOT_ATTEMPTED = "not attempted"

# The one result that unlocks the dump rows. Every other line result_line() can return
# names a failure, so the gate is equality against this rather than a list of failures
# that a new failure mode could quietly fall outside of.
READY_RESULT = "ready to dump"

HARNESS_NAMES = {0: "not connected", 1: "normal", 2: "flipped"}

# The four services that came back silent on the 2026-07-25 Corolla sweep while
# thirteen others answered with data or a precise NRC. That sweep ran on param 0, the
# OBD-II multiplexed path, so a silence there measures the gateway as much as the ECU.
# Sending the same four on every answering route turns each silence into a comparison.
#
# SENT AS BARE SERVICE BYTES, IN EXTENDED, BEFORE THE PROGRAMMING ATTEMPT. A service
# byte with no sub-function has to be rejected on length, so the ECU answers without
# acting; all four were already sent to this EPS in July with nothing happening. Ahead
# of PROGRAMMING rather than after, so a bare 0x11 is never sitting in a session where
# a reset could take.
PROBE_SERVICES = (0x11, 0x28, 0x34, 0x85)

# What the probe's 0xF186 read should come back as: 0x03 is EXTENDED_DIAGNOSTIC, so
# reading it means the session survived the four service probes above it. Any other
# value, a silence or an NRC means the session lapsed or the ECU stopped answering,
# and either one makes that route's silences unattributable. Only the unexpected case
# earns a line in the block.
EXPECTED_LIVENESS = "03"

# Ladder stages in the order the screenshot prints them. The PROGRAMMING repeat is
# recorded separately in the JSON but folded into one "Programming session" line, so
# the block matches the six-line shape owners are asked to screenshot.
STAGE_LABELS = (
  ("default", "Default session"),
  ("extended", "Extended session"),
  ("programming", "Programming session"),
  ("seed", "Security seed"),
  ("unlock", "Security unlock"),
  ("dump", "Test dump"),
)


def _noop(*args, **kwargs) -> None:
  pass


def blank_report(stamp=None) -> dict:
  """A report with every step at `not attempted`, so a run that dies partway is
  readable rather than silently short."""
  return {
    "stamp": stamp or datetime.now().strftime("%Y%m%d-%H%M%S"),
    "ecu_serial": "",
    "panda": {},
    "sweep": [],
    "probes": [],
    "route": {},
    "identity": {},
    "traffic": [],
    "traffic_param": None,
    "stages": {name: NOT_ATTEMPTED for name, _ in STAGE_LABELS},
    "stages_extra": {},
    "dump": {},
    "error": "",
  }


# --- Pure rendering, off-device testable ---


def result_line(report: dict) -> str:
  """One plain-language verdict. Never mentions a memory address or a byte value."""
  stages = report.get("stages", {})
  dump = report.get("dump") or {}

  if stages.get("dump", NOT_ATTEMPTED) != NOT_ATTEMPTED and dump.get("frames"):
    return READY_RESULT
  if stages.get("unlock") == "blocked":
    return "this ECU already rejected a key, so no more keys will be sent"
  if stages.get("dump", NOT_ATTEMPTED) != NOT_ATTEMPTED:
    return "the exploit ran but no dump frames came back"
  if str(stages.get("unlock", NOT_ATTEMPTED)).startswith("NRC"):
    return "the ECU rejected the security key"
  if stages.get("unlock", NOT_ATTEMPTED) != NOT_ATTEMPTED:
    return "the security unlock did not complete"
  if stages.get("seed", NOT_ATTEMPTED) not in (NOT_ATTEMPTED, "received"):
    return "the ECU refused to hand out a security seed"
  for name in ("programming", "extended", "default"):
    outcome = stages.get(name, NOT_ATTEMPTED)
    if outcome not in (NOT_ATTEMPTED, "opened"):
      return f"the {name} session did not open"
  if report.get("sweep") and not report.get("route"):
    return "the steering ECU never answered on any bus"
  if not report.get("panda"):
    return "preflight has not run yet"
  return "preflight did not finish"


def _sweep_lines(report: dict) -> list:
  """`param 0: bus 1` style lines, one per param, `none` when nothing answered."""
  lines = []
  for param in SWEEP_PARAMS:
    answered = [str(e["bus"]) for e in report.get("sweep", [])
                if e.get("param") == param and e.get("answered")]
    if not report.get("sweep"):
      shown = NOT_ATTEMPTED
    elif answered:
      shown = "bus " + ", ".join(answered)
    else:
      shown = "none"
    lines.append(f"param {param}: {shown}")
  return lines


def _outcome_token(value) -> str:
  """Compact form for the probe grid, so two routes fit one phone screen."""
  text = str(value)
  if text in ("opened", "answered"):
    return "ok"
  if text.startswith("NRC 0x"):
    return "NRC " + text[6:]
  if text == "MessageTimeoutError":
    return "silent"
  if text.endswith("Error"):
    return "err"
  return text


def _probe_lines(report: dict) -> list:
  """One stanza per probed route: the ladder, the four services, and a liveness line
  only when liveness failed.

  A failed liveness is what makes that route's silences unattributable, so it earns a
  line; a route that was still answering at the end of its block does not need one.
  """
  probes = report.get("probes") or []
  if not probes:
    return []
  out = ["", "Route probes"]
  for probe in probes:
    used = "  <-- used" if probe.get("chosen") else ""
    out.append(f"  bus {probe.get('bus')} param {probe.get('param')}{used}")
    ladder = " / ".join(_outcome_token(probe.get(key, NOT_ATTEMPTED))
                        for key in ("default", "extended", "programming"))
    out.append(f"    sessions  {ladder}")
    services = probe.get("services") or {}
    cells = [f"{sid:02x} {_outcome_token(services.get(f'0x{sid:02x}', NOT_ATTEMPTED))}"
             for sid in PROBE_SERVICES]
    out.append(f"    services  {cells[0]:<12}{cells[1]}")
    out.append(f"              {cells[2]:<12}{cells[3]}")
    liveness = probe.get("liveness", "")
    if liveness and liveness not in (EXPECTED_LIVENESS, NOT_ATTEMPTED):
      out.append(f"    liveness  {_outcome_token(liveness)}")
  return out


def render_screenshot(report: dict) -> str:
  """The block pinned above the live log. Plain language, hex only for identifiers.

  Pure: same report in, same text out, so the page, the copy-as-text box and the
  saved JSON can never disagree, and it is testable without a car.
  """
  result = result_line(report)
  out = [f"RESULT: {result}", ""]

  # `route` now means the route whose probe opened PROGRAMMING, so it is empty on a car
  # whose ECU answered perfectly well and then stopped there. The ECU line reads off
  # the sweep, which is what actually measured whether anything answered.
  route = report.get("route") or {}
  answering = _answering_pairs(report.get("sweep") or [])
  if route:
    eps = f"answered on bus {route['bus']}"
  elif answering:
    buses = sorted({bus for bus, _ in answering})
    eps = "answered on bus " + ", ".join(str(bus) for bus in buses)
  elif report.get("sweep"):
    eps = "no answer on any bus"
  else:
    eps = NOT_ATTEMPTED
  panda = report.get("panda") or {}
  if panda:
    harness = HARNESS_NAMES.get(panda.get("harness_status"), "unknown")
    panda_line = f"{panda.get('dongle') or 'unknown'}, harness {harness}"
  else:
    panda_line = NOT_ATTEMPTED

  sweep_lines = _sweep_lines(report)
  out.append(f"{'Steering ECU':<17}{eps}")
  out.append(f"{'Buses answering':<17}{sweep_lines[0]}")
  for extra in sweep_lines[1:]:
    out.append(f"{'':<17}{extra}")
  out.append(f"{'Panda':<17}{panda_line}")
  out.append("")

  stages = report.get("stages", {})
  for name, label in STAGE_LABELS:
    out.append(f"{label:<21}{stages.get(name, NOT_ATTEMPTED)}")

  identity = report.get("identity") or {}
  part = identity.get("app_sw_id") or ""
  serial = identity.get("ecu_serial") or ""
  if part or serial:
    out.append("")
    if part:
      out.append(f"{'ECU part number':<17}{part}")
    if serial:
      out.append(f"{'ECU serial':<17}{serial}")

  out.extend(_probe_lines(report))

  if result != READY_RESULT:
    out.append("")
    out.append("Send this screenshot to Calvin.")
  return "\n".join(out)


# --- The run ---


def _sweep(panda, uds_module, log) -> list:
  """DEFAULT session at 0x7a1 on every bus under both params.

  DEFAULT is the session an ECU is already in, so the sweep asks the one question
  that changes nothing whether it is answered or refused.
  """
  from opendbc.car.structs import CarParams
  UdsClient = uds_module.UdsClient
  SESSION_TYPE = uds_module.SESSION_TYPE
  errors = (uds_module.InvalidServiceIdError, uds_module.InvalidSubAddressError,
            uds_module.InvalidSubFunctionError, uds_module.MessageTimeoutError,
            uds_module.NegativeResponseError)

  results = []
  for param in SWEEP_PARAMS:
    panda.set_safety_mode(CarParams.SafetyModel.elm327, param)
    # The param selects which pin pair FDCAN2 rides on, so let the transceivers
    # settle before asking; a request sent into the switch is a false silence.
    time.sleep(0.1)
    for bus in SWEEP_BUSES:
      uds = UdsClient(panda, ADDR, ADDR + 8, bus, timeout=0.1,
                      response_pending_timeout=0.1)
      entry = {"bus": bus, "param": param, "answered": False, "detail": "silent"}
      try:
        uds.diagnostic_session_control(SESSION_TYPE.DEFAULT)
        entry.update(answered=True, detail="opened")
      except uds_module.NegativeResponseError as e:
        # An NRC is still an answer: something is there and it replied.
        entry.update(answered=True, detail=f"NRC 0x{e.error_code:02x}")
      except errors as e:
        entry["detail"] = type(e).__name__
      results.append(entry)
      log(f"  param {param} bus {bus}: {entry['detail']}")
  return results


def _answering_pairs(sweep) -> list:
  """Answering (bus, param) pairs, DEFAULT_ROUTE first when it is among them."""
  pairs = []
  for entry in sweep:
    pair = (entry.get("bus"), entry.get("param"))
    if entry.get("answered") and pair not in pairs:
      pairs.append(pair)
  if preflight_store.DEFAULT_ROUTE in pairs:
    pairs.remove(preflight_store.DEFAULT_ROUTE)
    pairs.insert(0, preflight_store.DEFAULT_ROUTE)
  return pairs


def _probe_route(panda, uds_module, bus, param, log) -> dict:
  """Session ladder plus the four silent services on one (bus, param) pair.

  Order: DEFAULT, EXTENDED, the four services, a 0xF186 read, EXTENDED again,
  PROGRAMMING, then DEFAULT to leave the ECU where the next probe and the exploit
  expect it.

  The 0xF186 read does two jobs. It says the ECU is still answering, so a silence in
  the four services above it is attributable to the route rather than to an EPS that
  dropped out mid-block. And it returns the active session byte, so a session that
  lapsed while those four timed out shows up as a value instead of a guess.

  EXTENDED is re-sent before PROGRAMMING for the 2026-07-24 reason: stacked timeouts
  in preamble_probe pushed PROGRAMMING more than six seconds past the EXTENDED request
  with no tester-present, and that run's own NRCs show it went out from a lapsed
  session. Re-asserting costs one request and removes the confound.

  Same timeout (0.1) and same 0.5/0.7 settles the dumpers use, so a PROGRAMMING answer
  the exploit would have caught is not missed by a stricter probe.
  """
  from opendbc.car.structs import CarParams
  UdsClient = uds_module.UdsClient
  SESSION_TYPE = uds_module.SESSION_TYPE
  DID = uds_module.DATA_IDENTIFIER_TYPE
  errors = (uds_module.InvalidServiceIdError, uds_module.InvalidSubAddressError,
            uds_module.InvalidSubFunctionError, uds_module.MessageTimeoutError,
            uds_module.NegativeResponseError)

  probe = {"bus": bus, "param": param, "chosen": False,
           "default": NOT_ATTEMPTED, "extended": NOT_ATTEMPTED,
           "extended_again": NOT_ATTEMPTED, "programming": NOT_ATTEMPTED,
           "services": {}, "liveness": NOT_ATTEMPTED}

  panda.set_safety_mode(CarParams.SafetyModel.elm327, param)
  time.sleep(0.1)
  uds = UdsClient(panda, ADDR, ADDR + 8, bus, timeout=0.1,
                  response_pending_timeout=0.1)
  log(f"  bus {bus} param {param}:")

  def call(fn, ok):
    try:
      value = fn()
    except uds_module.NegativeResponseError as e:
      return f"NRC 0x{e.error_code:02x}"
    except uds_module.MessageTimeoutError:
      return "silent"
    except errors as e:
      return type(e).__name__
    return value if ok is None else ok

  def session(kind):
    return call(lambda: uds.diagnostic_session_control(kind), "opened")

  probe["default"] = session(SESSION_TYPE.DEFAULT)
  log(f"    default: {probe['default']}")
  if probe["default"] != "opened":
    return probe
  time.sleep(0.5)

  probe["extended"] = session(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
  log(f"    extended: {probe['extended']}")
  if probe["extended"] != "opened":
    return probe
  time.sleep(0.7)

  for sid in PROBE_SERVICES:
    outcome = call(lambda s=sid: uds._uds_request(s), "answered")
    probe["services"][f"0x{sid:02x}"] = outcome
    log(f"    service 0x{sid:02x}: {outcome}")

  raw = call(lambda: uds.read_data_by_identifier(DID.ACTIVE_DIAGNOSTIC_SESSION), None)
  probe["liveness"] = _printable(raw) if isinstance(raw, (bytes, bytearray)) else raw
  log(f"    active session: {probe['liveness']}")

  probe["extended_again"] = session(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
  if probe["extended_again"] != "opened":
    log(f"    extended again: {probe['extended_again']}")
  time.sleep(0.7)

  probe["programming"] = session(SESSION_TYPE.PROGRAMMING)
  log(f"    programming: {probe['programming']}")

  # Back to DEFAULT so the next probe starts clean and the exploit's own ladder is not
  # entering from a session this one left open.
  session(SESSION_TYPE.DEFAULT)
  return probe


def _probe_routes(panda, uds_module, sweep, log) -> list:
  """Probe every answering pair, stopping early only on a proven route.

  When DEFAULT_ROUTE answered it is probed first, and a PROGRAMMING there ends the
  loop: that is the route 74 Sienna runs already use, so there is nothing a second
  probe could tell those owners and no reason to spend their car time on it. Every
  other car gets all of its answering pairs probed, because the cross-route comparison
  is the measurement.
  """
  probes = []
  for index, (bus, param) in enumerate(_answering_pairs(sweep)):
    probe = _probe_route(panda, uds_module, bus, param, log)
    probes.append(probe)
    if (index == 0 and (bus, param) == preflight_store.DEFAULT_ROUTE
        and probe["programming"] == "opened"):
      break
  return probes


def _select_route(probes) -> dict:
  """The first probed route that opened PROGRAMMING, marked as chosen. {} when none
  did, which means no route could have run the exploit."""
  for probe in probes:
    if probe.get("programming") == "opened":
      probe["chosen"] = True
      return {"bus": probe["bus"], "param": probe["param"]}
  return {}


def _probe_rank(probe) -> int:
  """How far up the ladder a probe reached. Ranks which route's outcome to print."""
  rank = 0
  for key in ("default", "extended", "programming"):
    if probe.get(key) != "opened":
      break
    rank += 1
  return rank


def _fold_stages(report) -> None:
  """Copy one probe's ladder into the stage lines the screenshot prints.

  The chosen route when there is one, otherwise whichever route reached furthest, so a
  car where nothing opened PROGRAMMING still reports the best it managed instead of
  three `not attempted` lines. `result_line` reads those stages, so this is also what
  turns "no route opened PROGRAMMING" into the programming-session verdict.
  """
  probes = report.get("probes") or []
  if not probes:
    return
  best = next((p for p in probes if p.get("chosen")), None)
  if best is None:
    best = max(probes, key=_probe_rank)
  for key in ("default", "extended", "programming"):
    report["stages"][key] = best.get(key, NOT_ATTEMPTED)


def _identity(panda, uds_module, route, log) -> dict:
  """0xF181, 0xF18C, 0xF186. Free reads, no security, no state change."""
  from opendbc.car.structs import CarParams
  UdsClient = uds_module.UdsClient
  DID = uds_module.DATA_IDENTIFIER_TYPE
  errors = (uds_module.InvalidServiceIdError, uds_module.InvalidSubAddressError,
            uds_module.InvalidSubFunctionError, uds_module.MessageTimeoutError,
            uds_module.NegativeResponseError)

  panda.set_safety_mode(CarParams.SafetyModel.elm327, route["param"])
  uds = UdsClient(panda, ADDR, ADDR + 8, route["bus"], timeout=0.1,
                  response_pending_timeout=0.1)
  wanted = (
    ("app_sw_id", DID.APPLICATION_SOFTWARE_IDENTIFICATION),
    ("ecu_serial", DID.ECU_SERIAL_NUMBER),
    ("active_session", DID.ACTIVE_DIAGNOSTIC_SESSION),
  )
  out = {}
  for name, did in wanted:
    try:
      raw = uds.read_data_by_identifier(did)
    except uds_module.NegativeResponseError as e:
      out[name] = f"NRC 0x{e.error_code:02x}"
    except errors as e:
      out[name] = type(e).__name__
    else:
      out[name] = _printable(raw)
    log(f"  {name}: {out[name]}")
  return out


def _printable(raw: bytes) -> str:
  """ASCII when the bytes are ASCII, hex otherwise. Identifiers only."""
  try:
    text = raw.decode("ascii")
  except (UnicodeDecodeError, AttributeError):
    return raw.hex() if isinstance(raw, (bytes, bytearray)) else str(raw)
  stripped = "".join(c for c in text if c.isprintable()).strip()
  return stripped or raw.hex()


def _traffic(panda, seconds, log) -> list:
  """Per-bus frame count, distinct arbitration IDs and 0x0F sync count.

  Reported only. A zero sync count never gates the outcome: SecOC signs in READY
  Mode and preflight runs in Not Ready To Drive, so zero is the expected reading.
  """
  counts = {}
  begin = time.time()
  while time.time() - begin < seconds:
    for addr, *_, bus in panda.can_recv():
      entry = counts.setdefault(bus, {"bus": bus, "frames": 0, "ids": set(), "sync": 0})
      entry["frames"] += 1
      entry["ids"].add(addr)
      if addr == SYNC_ADDR:
        entry["sync"] += 1
    time.sleep(0.005)

  out = []
  for bus in sorted(counts):
    entry = counts[bus]
    out.append({"bus": bus, "frames": entry["frames"], "ids": len(entry["ids"]),
                "sync": entry["sync"]})
    log(f"  bus {bus}: {entry['frames']} frames, {len(entry['ids'])} ids, "
        f"{entry['sync']} sync")
  if not out:
    log("  no traffic on any bus")
  return out


def run(log_cb=None, report_cb=None, progress_cb=None) -> dict:
  """Run every step in order and return the report. Raises NotAGNOSError off-device.

  log_cb(text) receives one live-log line at a time. report_cb(report) is called after
  each step so a page polling mid-run can re-render the screenshot block from partial
  results. progress_cb is forwarded to the dump so byte progress still moves.
  """
  if not is_agnos():
    raise NotAGNOSError

  log = log_cb or _noop
  publish = report_cb or _noop
  report = blank_report()
  publish(report)

  from opendbc.car import uds as uds_module

  # Same takeover preamble as the dumpers: the manager restarts pandad, which would
  # take the panda back mid-run.
  log("Taking over the panda.")
  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)

  panda = TSKExtractor._connect_panda()
  try:
    # 1. Panda.
    log("Panda:")
    panda_info = {}
    try:
      serial = panda.get_serial()
      panda_info["dongle"] = serial[0]
      panda_info["hw_serial"] = serial[1]
    except Exception as e:
      panda_info["dongle"] = ""
      panda_info["error"] = type(e).__name__
    try:
      panda_info["version"] = panda.get_version()
    except Exception:
      panda_info["version"] = ""
    try:
      panda_info["harness_status"] = panda.health().get("car_harness_status")
    except Exception:
      panda_info["harness_status"] = None
    report["panda"] = panda_info
    log(f"  {panda_info.get('dongle') or 'unknown'}, firmware "
        f"{panda_info.get('version') or 'unknown'}, harness "
        f"{HARNESS_NAMES.get(panda_info.get('harness_status'), 'unknown')}")
    publish(report)

    # 2. Bus sweep, both params.
    log("Bus sweep (default session on 0x7a1):")
    report["sweep"] = _sweep(panda, uds_module, log)
    publish(report)
    pairs = _answering_pairs(report["sweep"])
    if not pairs:
      report["error"] = "The steering ECU did not answer on any bus under either param."
      log(report["error"])
      return _finish(report)

    # 3. Identity, on the first answering pair and BEFORE the probe. The part number
    # and the serial are the most useful things a failed run can carry, and they are
    # free reads, so they must not sit behind a step that can end the run.
    log("Identity:")
    first_route = {"bus": pairs[0][0], "param": pairs[0][1]}
    report["identity"] = _identity(panda, uds_module, first_route, log)
    serial_value = report["identity"].get("ecu_serial", "")
    if serial_value and not serial_value.startswith(("NRC ", "Message", "Invalid",
                                                     "silent")):
      report["ecu_serial"] = serial_value
    publish(report)

    # 4. Traffic, before the probe and the exploit: both flood the bus and would drown
    # it, and a run that ends at the probe should still ship the bus picture.
    log(f"Traffic ({TRAFFIC_SECONDS:.0f}s):")
    report["traffic"] = _traffic(panda, TRAFFIC_SECONDS, log)
    report["traffic_param"] = first_route["param"]
    publish(report)

    # 5. Route probe. PROGRAMMING is what picks, since a DEFAULT session answers on
    # any route that reaches the ECU at all.
    log("Route probe:")
    report["probes"] = _probe_routes(panda, uds_module, report["sweep"], log)
    report["route"] = _select_route(report["probes"])
    _fold_stages(report)
    publish(report)

    # Persist the route and the serial BEFORE the exploit, so the log entries the dump
    # writes are keyed to this ECU and a run that dies in the dump still leaves the
    # measured route behind. When no route opened PROGRAMMING the first answering pair
    # is stored instead, which keeps the serial attributed to this car; the dump rows
    # gate on the result rather than on a route existing, so storing it enables
    # nothing on its own.
    stored = report["route"] or first_route
    preflight_store.save_route(
      stored["bus"], stored["param"],
      panda_serial=panda_info.get("dongle"),
      harness_status=panda_info.get("harness_status"),
      ecu_serial=report["ecu_serial"] or preflight_store.UNATTRIBUTED,
      stamp=report["stamp"])

    if not report["route"]:
      report["error"] = ("No route opened the programming session, so the exploit was "
                         "not attempted and no key was sent.")
      log(report["error"])
      return _finish(report)
    log(f"  using bus {report['route']['bus']}, param {report['route']['param']}")
  finally:
    # Release the handle before dump_range opens its own; two live handles on one
    # panda is a USB conflict, and dump() always connects for itself.
    TSKExtractor._close_panda()

  # 6. The exploit, on the route whose probe opened PROGRAMMING. One call, so one key.
  profile = PROFILES[EXPLOIT_PROFILE]
  log(f"Exploit run: {profile.label} {profile.start:#010x}-{profile.end:#010x}")

  def stage(name, outcome):
    if name in report["stages"]:
      report["stages"][name] = outcome
    else:
      report["stages_extra"][name] = outcome
    # The repeat is the same transition; a failure on it is the programming result.
    if name == "programming_repeat" and outcome != "opened":
      report["stages"]["programming"] = outcome
    log(f"  {name}: {outcome}")
    publish(report)

  try:
    result = dump_range(EXPLOIT_PROFILE, progress_cb=progress_cb,
                        route=(report["route"]["bus"], report["route"]["param"]),
                        ecu_serial=report["ecu_serial"] or preflight_store.UNATTRIBUTED,
                        stage_cb=stage)
    report["dump"] = result
    log(result.get("message", ""))
  except RetryError as e:
    report["error"] = str(e)
    log(str(e))
  except Exception as e:
    report["error"] = f"{type(e).__name__}: {e}"
    log(report["error"])
  finally:
    TSKExtractor._close_panda()

  return _finish(report)


def _finish(report) -> dict:
  report["result"] = result_line(report)
  report["screenshot"] = render_screenshot(report)
  report["path"] = preflight_store.save_report(report)
  return report


def run_mock(log_cb=None, report_cb=None, progress_cb=None) -> dict:
  """Off-device stand-in. Exercises the same report shape and the same renderer, so a
  laptop run checks the screenshot block, the result line and the JSON write."""
  log = log_cb or _noop
  publish = report_cb or _noop
  cb = progress_cb or _noop
  report = blank_report()
  publish(report)

  log("Taking over the panda.")
  time.sleep(0.3)
  log("Panda:")
  report["panda"] = {"dongle": "mockdongle000000", "hw_serial": "MOCK000000",
                     "version": "DEV-mock-DEBUG", "harness_status": 1}
  log("  mockdongle000000, firmware DEV-mock-DEBUG, harness normal")
  publish(report)

  # A TWO-ROUTE CAR, deliberately. The mock fakes the shape Span's Corolla measured on
  # 2026-08-19: bus 1 answering a DEFAULT session under both params. A single-route
  # mock would never reach the probe loop, the selection or the fold, so the laptop
  # pass would exercise none of the code this page exists for.
  log("Bus sweep (default session on 0x7a1):")
  report["sweep"] = []
  for param in SWEEP_PARAMS:
    for bus in SWEEP_BUSES:
      answered = (bus == 1)
      report["sweep"].append({"bus": bus, "param": param, "answered": answered,
                              "detail": "opened" if answered else "silent"})
      log(f"  param {param} bus {bus}: {'opened' if answered else 'silent'}")
      time.sleep(0.05)
  publish(report)

  log("Identity:")
  report["identity"] = {"app_sw_id": "MOCK12080000", "ecu_serial": "MOCK012N50E12H03",
                        "active_session": "01"}
  report["ecu_serial"] = report["identity"]["ecu_serial"]
  for name, value in report["identity"].items():
    log(f"  {name}: {value}")
  publish(report)

  log("Traffic (3s):")
  report["traffic"] = [{"bus": 0, "frames": 4212, "ids": 22, "sync": 0},
                       {"bus": 1, "frames": 6, "ids": 2, "sync": 0},
                       {"bus": 2, "frames": 4212, "ids": 22, "sync": 0}]
  report["traffic_param"] = 0
  for entry in report["traffic"]:
    log(f"  bus {entry['bus']}: {entry['frames']} frames, {entry['ids']} ids, "
        f"{entry['sync']} sync")
  publish(report)

  # The OBD route answers a DEFAULT session and stops at PROGRAMMING; the harness route
  # goes all the way. Which is the split the probe exists to find.
  log("Route probe:")
  report["probes"] = []
  for param, opens in ((0, False), (1, True)):
    probe = {"bus": 1, "param": param, "chosen": False, "default": "opened",
             "extended": "opened", "extended_again": "opened",
             "programming": "opened" if opens else "silent",
             "services": {f"0x{sid:02x}": ("NRC 0x13" if opens else "silent")
                          for sid in PROBE_SERVICES},
             "liveness": "03"}
    report["probes"].append(probe)
    log(f"  bus 1 param {param}:")
    log(f"    programming: {probe['programming']}")
    publish(report)
    time.sleep(0.2)
  report["route"] = _select_route(report["probes"])
  _fold_stages(report)
  publish(report)

  # Same persistence the real run does, so a laptop exercises the gate the UI reads.
  preflight_store.save_route(report["route"]["bus"], report["route"]["param"],
                             panda_serial=report["panda"].get("dongle"),
                             harness_status=report["panda"].get("harness_status"),
                             ecu_serial=report["ecu_serial"], stamp=report["stamp"])
  log(f"  using bus {report['route']['bus']}, param {report['route']['param']}")

  profile = PROFILES[EXPLOIT_PROFILE]
  log(f"Exploit run: {profile.label} {profile.start:#010x}-{profile.end:#010x}")
  for name in ("default", "extended", "programming", "programming_repeat"):
    if name in report["stages"]:
      report["stages"][name] = "opened"
    log(f"  {name}: opened")
    publish(report)
    time.sleep(0.15)
  report["stages"]["seed"] = "received"
  log("  seed: received")
  publish(report)
  report["stages"]["unlock"] = "accepted"
  log("  unlock: accepted")
  publish(report)

  total = profile.total
  for done in (total // 4, total // 2, total * 3 // 4, total):
    time.sleep(0.3)
    cb(status="running", frames=done // 4, bytes_done=done, total=total)
  report["stages"]["dump"] = f"{total} of {total} bytes"
  report["dump"] = {"status": "complete", "frames": total // 4, "bytes": total,
                    "total": total, "dump_path": "", "message": "Dump complete (mock)."}
  log("Dump complete (mock).")

  return _finish(report)
