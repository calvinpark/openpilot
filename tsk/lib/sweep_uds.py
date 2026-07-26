#!/usr/bin/env python3
"""Exhaustive UDS boundary sweep — every service byte, every sub-function, no skip list.

The Corolla EPS (8965F1208000, bus 1) answers every read service and goes completely
silent on the reprogramming set (0x10 sub-function 02, 0x28, 0x34, 0x85). Silence is not
a refusal — this EPS says "no" freely and precisely elsewhere — so the silent set is
either a filter on the path or firmware that doesn't implement those services. Mapping
exactly where the boundary falls is what separates those, and a curated list of
"meaningful" services can't do it: ISO 14229 reserves ranges for manufacturer-specific
services, and a Toyota-proprietary service is precisely where a way past a reflash block
would live.

So: every service 0x00-0xFF, every sub-function 0x00-0xFF, in both sessions, with no
service omitted for being dangerous, undocumented, or uninteresting.

**Safety is a constraint on how a value is sent, never on whether it is sent.**
  - The service-existence layer sends the BARE service byte. A service that takes a
    sub-function sees a malformed request and answers NRC 0x13 without acting; a bare
    byte cannot name a valid sub-function, so it is the least-active possible probe.
  - DEFAULT session is swept before EXTENDED. Nearly everything destructive is session
    gated, so the first pass is the safest one.
  - The sub-function layer CAN name real operations (0x11 01 resets the ECU, 0x28 03
    disables comms). It runs anyway — that is the point of the sweep — but each service
    block is followed by a restore (DEFAULT session, 0x28 enable rx/tx, 0x85 DTC on) and
    a liveness check, and the page warns which operations are reachable.

**Coverage is bounded by a deadline, never by a skip list.** Each run takes
`budget_seconds` (5 minutes in Not Ready to Drive, before the 12V sags) and stops
cleanly at the frontier. Every result is appended to `uds_sweep.ndjson` as it arrives,
so a mid-run power loss costs nothing, and the next run reads the file, skips what is
already answered, and continues. Two or three short sessions compose into one full map.

Four outcomes, all informative:
  positive  — supported and reachable
  nrc 0x11  — the ECU says it does not have that service. A real answer.
  nrc other — the service EXISTS and we asked wrong (0x13/0x22/0x31/0x7e/0x7f). The most
              interesting bucket, and where an undocumented service shows up.
  silent    — the wall

The response timeout is measured, not guessed: a known-good request is timed at startup
and the silence threshold is set to a multiple of the observed round trip. A slow service
still emits NRC 0x78 (response pending) quickly, which extends the wait, so a short
window rarely manufactures a false silence — and the last stage re-probes everything
classified silent at 10x the timeout anyway.

is_agnos-gated; the server mocks it off-device.
"""
import json
import os
import time

from tsk.lib.env import CACHE_DIR, is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.dump_dataflash import ADDR
from tsk.lib.dump_diag import CANDIDATE_BUSES

SWEEP_DIR = f"{CACHE_DIR}/tsk/uds-sweep"
SWEEP_PATH = f"{SWEEP_DIR}/uds_sweep.ndjson"

DEFAULT_BUDGET = 300.0        # 5 minutes — the Not Ready to Drive 12V window
CALIBRATION_SAMPLES = 5
MIN_TIMEOUT = 0.05
MAX_TIMEOUT = 0.30
TIMEOUT_MULTIPLE = 10         # silence threshold = this x the observed round trip
PENDING_EXTRA = 1.0           # extra wait granted when the ECU says response-pending
LONG_TIMEOUT_MULTIPLE = 10    # the re-probe pass multiplies the calibrated timeout by this

SERVICE_RANGE = range(0x00, 0x100)
SUBFUNCTION_RANGE = range(0x00, 0x100)
ADDRESS_RANGE = range(0x700, 0x800)

# DID blocks worth a scoped pass. The full 16-bit space is 65536 requests (~16 min) and
# does not fit the window; these three cover identity, the block Willem's payload upload
# writes, and the manufacturer-specific range.
DID_BLOCKS = [(0xF100, 0xF1FF, "identity"), (0x0200, 0x02FF, "willem"),
              (0xFD00, 0xFEFF, "manufacturer")]

# Known silent on this EPS — re-tested against every other responder found on the bus,
# which is the gateway-vs-EPS discriminator: another module going silent on the same
# services would mean something on the path is filtering, and a repin could bypass it.
# RUN in-car 2026-07-25: of 13 responders on bus 1, twelve go silent on all four and
# 0x7f1 returns a proper NRC to all four. That does NOT settle it either way. If all
# thirteen sit on the panda's physical segment, no filtering is possible and the drop is
# per-ECU; but a routing gateway filters BY DESTINATION, so a "no reflash to the EPS"
# policy answering for itself at 0x7f1 produces exactly the same pattern. Which of those
# is true depends on whether those addresses are on our wire or proxied, and that is
# unverified. The discriminator is a READY background-traffic capture: a module that
# answers diagnostics but never transmits periodic frames on our segment is proxied.
# See tsk/COROLLA_INVESTIGATION.md section 9.9.
SILENT_SET = [(b"\x10\x02", "programming session"), (b"\x28", "communication control"),
              (b"\x34", "request download"), (b"\x85", "control DTC setting")]

CALIBRATION_REQUEST = b"\x22\xf1\x81"


def _noop(**kwargs) -> None:
  pass


def parse_isotp_frame(data: bytes):
  """First-frame parse only — service + NRC live in the first frame either way, and
  skipping reassembly keeps the sweep fast enough to finish inside the window."""
  if not data:
    return None
  pci = data[0] >> 4
  if pci == 0x0:
    n = data[0] & 0x0F
    body = bytes(data[1:1 + n])
  elif pci == 0x1:
    body = bytes(data[2:])
  else:
    return None
  if not body:
    return None
  if body[0] == 0x7F:
    sid = body[1] if len(body) > 1 else -1
    nrc = body[2] if len(body) > 2 else -1
    return {"outcome": "nrc", "sid": sid, "nrc": nrc, "raw": body.hex()}
  return {"outcome": "positive", "sid": body[0], "nrc": -1, "raw": body.hex()}


def ask(panda, bus: int, tx: int, rx: int, payload: bytes, timeout: float) -> dict:
  """Send a raw request and classify the first response frame. Never raises."""
  try:
    panda.can_recv()   # drain, so a stale frame is not attributed to this request
  except Exception:
    pass

  from opendbc.car.isotp import isotp_send
  t0 = time.time()
  try:
    isotp_send(panda, payload, tx, bus=bus)
  except Exception as e:
    return {"outcome": "send_error", "sid": -1, "nrc": -1, "raw": "",
            "detail": type(e).__name__, "ms": 0}

  deadline = t0 + timeout
  while time.time() < deadline:
    try:
      frames = panda.can_recv()
    except Exception:
      break
    for addr, *_rest, data, rbus in frames:
      if rbus >= 0x80 or rbus != bus or addr != rx:
        continue   # rbus >= 0x80 is the panda's echo of our own transmit
      parsed = parse_isotp_frame(bytes(data))
      if parsed is None:
        continue
      if parsed["outcome"] == "nrc" and parsed["nrc"] == 0x78:
        deadline = time.time() + PENDING_EXTRA   # response pending: grant more time
        continue
      parsed["ms"] = int((time.time() - t0) * 1000)
      return parsed
  return {"outcome": "silent", "sid": -1, "nrc": -1, "raw": "",
          "ms": int((time.time() - t0) * 1000)}


class Recorder:
  """Appends every result to disk as it arrives and knows what a prior run answered."""

  def __init__(self, path: str = SWEEP_PATH):
    self.path = path
    self.done: set = set()
    self.count = 0
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
      with open(path) as f:
        for line in f:
          try:
            rec = json.loads(line)
          except Exception:
            continue
          self.done.add(rec.get("key", ""))
          self.count += 1
    except FileNotFoundError:
      pass
    self.fh = open(path, "a")

  def seen(self, key: str) -> bool:
    return key in self.done

  def write(self, key: str, **fields) -> None:
    rec = {"key": key}
    rec.update(fields)
    self.fh.write(json.dumps(rec) + "\n")
    self.fh.flush()
    self.done.add(key)
    self.count += 1

  def close(self) -> None:
    try:
      self.fh.close()
    except Exception:
      pass


def sweep(progress_cb=None, budget_seconds: float = DEFAULT_BUDGET, mode: str = "nrtd") -> dict:
  """Run the sweep until the budget runs out. Returns:
    {status, panda, eps_bus, timeout_ms, stages[], answering[], silent[], responders[],
     records, frontier, message}
  status is "complete" (nothing left to ask) | "partial" (budget hit, resume to continue)
  | "unreachable" | "failed". Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop
  started = time.time()

  def remaining() -> float:
    return budget_seconds - (time.time() - started)

  stages: list = []
  answering: list = []
  silent: list = []
  responders: list = []
  result = {
    "status": "failed", "panda": "", "eps_bus": -1, "timeout_ms": 0, "stages": stages,
    "answering": answering, "silent": silent, "responders": responders, "records": 0,
    "frontier": "", "mode": mode, "message": "",
  }

  from opendbc.car.structs import CarParams

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

  rec = Recorder()
  rx_of = lambda tx: tx + 8

  try:
    # --- find the EPS bus ---------------------------------------------------------
    eps_bus = None
    for cand in CANDIDATE_BUSES:
      r = ask(panda, cand, ADDR, rx_of(ADDR), b"\x10\x01", 0.3)
      if r["outcome"] in ("positive", "nrc"):
        eps_bus = cand
        break
    result["eps_bus"] = eps_bus if eps_bus is not None else -1
    if eps_bus is None:
      result.update(status="unreachable",
                    message="EPS did not answer on bus 0, 1, or 2. Re-enter Not Ready to "
                            "Drive and re-run.")
      return result

    # --- calibrate the silence threshold ------------------------------------------
    samples = []
    for _ in range(CALIBRATION_SAMPLES):
      r = ask(panda, eps_bus, ADDR, rx_of(ADDR), CALIBRATION_REQUEST, MAX_TIMEOUT)
      if r["outcome"] in ("positive", "nrc"):
        samples.append(r["ms"] / 1000.0)
    observed = sorted(samples)[len(samples) // 2] if samples else MIN_TIMEOUT
    timeout = min(MAX_TIMEOUT, max(MIN_TIMEOUT, observed * TIMEOUT_MULTIPLE))
    result["timeout_ms"] = int(timeout * 1000)
    stages.append({"name": "calibrate", "detail":
                   f"round trip {int(observed * 1000)} ms → timeout {int(timeout * 1000)} ms"})
    cb(steps=rec.count, last="calibrated", stage="calibrate")

    def set_session(sf: int) -> None:
      ask(panda, eps_bus, ADDR, rx_of(ADDR), bytes([0x10, sf]), timeout)

    def alive() -> bool:
      return ask(panda, eps_bus, ADDR, rx_of(ADDR), CALIBRATION_REQUEST,
                 timeout * 4)["outcome"] in ("positive", "nrc")

    def restore() -> None:
      for req in (b"\x28\x00\x01", b"\x85\x01", b"\x10\x01"):
        ask(panda, eps_bus, ADDR, rx_of(ADDR), req, timeout)

    def run_block(name, items, build, tx=ADDR, tmo=None, session=None):
      """items -> (key, payload). Stops at the deadline and records the frontier."""
      use = tmo if tmo is not None else timeout
      sent = 0
      for key, payload, label in (build(i) for i in items):
        if remaining() <= 0:
          result["frontier"] = f"{name}: stopped at {label}"
          return sent, False
        if rec.seen(key):
          continue
        r = ask(panda, eps_bus, tx, rx_of(tx), payload, use)
        rec.write(key, stage=name, session=session or "", label=label,
                  request=payload.hex(), **{k: r[k] for k in ("outcome", "sid", "nrc", "raw", "ms")})
        sent += 1
        if sent % 16 == 0:
          cb(steps=rec.count, last=label, stage=name)
      return sent, True

    # --- stage 1+2: every service byte, bare, in both sessions --------------------
    for session_name, sf in (("default", 0x01), ("extended", 0x03)):
      set_session(sf)
      n, finished = run_block(
        f"services/{session_name}", SERVICE_RANGE,
        lambda sid: (f"svc:{session_name}:{sid:02x}", bytes([sid]), f"service 0x{sid:02x}"),
        session=session_name)
      stages.append({"name": f"services/{session_name}", "detail": f"{n} sent"})
      cb(steps=rec.count, last=f"services {session_name}", stage="services")
      if not finished:
        break

    # Re-read the file to classify: which services answered, which stayed silent.
    answered_sids: set = set()
    silent_sids: set = set()
    try:
      with open(rec.path) as f:
        for line in f:
          try:
            r = json.loads(line)
          except Exception:
            continue
          if not r.get("key", "").startswith("svc:"):
            continue
          sid = int(r["key"].rsplit(":", 1)[1], 16)
          if r.get("outcome") in ("positive", "nrc") and r.get("nrc") != 0x11:
            answered_sids.add(sid)
          elif r.get("outcome") == "silent":
            silent_sids.add(sid)
    except FileNotFoundError:
      pass
    answering.extend(sorted(f"0x{s:02x}" for s in answered_sids))
    silent.extend(sorted(f"0x{s:02x}" for s in silent_sids))

    # --- stage 3: every sub-function of every service that answered ---------------
    # The boundary can run THROUGH a service rather than around it — 0x10 answers on
    # sub-functions 01/03/04 and is silent on 02 — so a service-level map alone misses it.
    if remaining() > 0:
      set_session(0x03)
      for sid in sorted(answered_sids):
        if remaining() <= 0:
          result["frontier"] = f"subfunctions: stopped before service 0x{sid:02x}"
          break
        n, finished = run_block(
          f"subfunctions/{sid:02x}", SUBFUNCTION_RANGE,
          lambda s, _sid=sid: (f"sub:{_sid:02x}:{s:02x}", bytes([_sid, s]),
                               f"0x{_sid:02x} sub 0x{s:02x}"),
          session="extended")
        restore()
        if not alive():
          stages.append({"name": f"subfunctions/{sid:02x}",
                         "detail": f"{n} sent — EPS stopped answering after this service"})
          result["frontier"] = f"subfunctions: EPS died on service 0x{sid:02x}"
          break
        set_session(0x03)
        stages.append({"name": f"subfunctions/{sid:02x}", "detail": f"{n} sent"})
        cb(steps=rec.count, last=f"sub-functions of 0x{sid:02x}", stage="subfunctions")
        if not finished:
          break

    # --- stage 4: scoped DID pass -------------------------------------------------
    if remaining() > 0:
      set_session(0x03)
      for lo, hi, block in DID_BLOCKS:
        if remaining() <= 0:
          result["frontier"] = f"dids: stopped before block {block}"
          break
        n, finished = run_block(
          f"dids/{block}", range(lo, hi + 1),
          lambda d, _b=block: (f"did:{d:04x}", bytes([0x22, d >> 8, d & 0xFF]),
                               f"DID 0x{d:04x}"),
          session="extended")
        stages.append({"name": f"dids/{block}", "detail": f"{n} sent"})
        cb(steps=rec.count, last=f"DIDs {block}", stage="dids")
        if not finished:
          break

    # --- stage 5: who else is on this bus, and do they go silent too --------------
    if remaining() > 0:
      # Inline rather than run_block: every item needs its own tx address.
      for a in ADDRESS_RANGE:
        if remaining() <= 0:
          result["frontier"] = f"addresses: stopped at 0x{a:03x}"
          break
        key = f"addr:{a:03x}"
        if rec.seen(key):
          continue
        r = ask(panda, eps_bus, a, rx_of(a), b"\x10\x01", timeout)
        rec.write(key, stage="addresses", label=f"address 0x{a:03x}",
                  request="1001", **{k: r[k] for k in ("outcome", "sid", "nrc", "raw", "ms")})
        if r["outcome"] in ("positive", "nrc"):
          responders.append(f"0x{a:03x}")
      stages.append({"name": "addresses", "detail": f"{len(responders)} responder(s)"})
      cb(steps=rec.count, last="address sweep", stage="addresses")

      # The discriminator: the same silent services against every other responder.
      for a_hex in list(responders):
        a = int(a_hex, 16)
        if a == ADDR or remaining() <= 0:
          continue
        for payload, label in SILENT_SET:
          key = f"cross:{a:03x}:{payload.hex()}"
          if rec.seen(key):
            continue
          r = ask(panda, eps_bus, a, rx_of(a), payload, timeout)
          rec.write(key, stage="cross", label=f"{a_hex} {label}", request=payload.hex(),
                    **{k: r[k] for k in ("outcome", "sid", "nrc", "raw", "ms")})
      cb(steps=rec.count, last="cross-ECU silent set", stage="cross")

    # --- stage 6: re-probe everything silent, at a much longer timeout ------------
    if remaining() > 0 and silent_sids:
      long_timeout = min(2.0, timeout * LONG_TIMEOUT_MULTIPLE)
      set_session(0x03)
      n, finished = run_block(
        "recheck", sorted(silent_sids),
        lambda sid: (f"recheck:{sid:02x}", bytes([sid]), f"recheck 0x{sid:02x}"),
        tmo=long_timeout, session="extended")
      stages.append({"name": "recheck", "detail": f"{n} sent at {int(long_timeout * 1000)} ms"})
      cb(steps=rec.count, last="recheck", stage="recheck")

    restore()
    result["records"] = rec.count
    if result["frontier"]:
      result.update(status="partial",
                    message=(f"Budget reached — {rec.count} results saved. {result['frontier']}. "
                             "Run this page again (Not Ready to Drive) and it resumes where it "
                             "stopped. Screenshot and send to Calvin."))
    else:
      result.update(status="complete",
                    message=(f"Sweep finished — {rec.count} results saved, "
                             f"{len(answering)} service(s) answering, {len(silent)} silent, "
                             f"{len(responders)} responder(s) on the bus. Screenshot and send "
                             "to Calvin."))
    return result

  except Exception as e:
    result.update(status="failed", records=rec.count,
                  message=f"Sweep aborted: {type(e).__name__}: {e} ({rec.count} results saved)")
    return result
  finally:
    rec.close()


def summarize(path: str = SWEEP_PATH) -> dict:
  """Pure — tally a persisted sweep. Off-device testable and shared with the READY pass,
  which builds its re-test work-list from these buckets."""
  out = {"records": 0, "positive": [], "nrc_11": [], "nrc_other": [], "silent": [],
         "responders": [], "condition_nrc": []}
  try:
    with open(path) as f:
      lines = f.readlines()
  except FileNotFoundError:
    return out
  for line in lines:
    try:
      r = json.loads(line)
    except Exception:
      continue
    out["records"] += 1
    key = r.get("key", "")
    label = r.get("label", key)
    outcome, nrc = r.get("outcome"), r.get("nrc", -1)
    if key.startswith("addr:") and outcome in ("positive", "nrc"):
      out["responders"].append(label)
      continue
    if outcome == "positive":
      out["positive"].append(label)
    elif outcome == "nrc" and nrc == 0x11:
      out["nrc_11"].append(label)
    elif outcome == "nrc":
      out["nrc_other"].append(label)
      if nrc in (0x22, 0x7E, 0x7F):
        out["condition_nrc"].append(label)
    elif outcome == "silent":
      out["silent"].append(label)
  return out
