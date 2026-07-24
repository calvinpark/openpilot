#!/usr/bin/env python3
"""CAN sniffer: a read-only diagnostic that tallies raw CAN traffic per bus.

collect_can.py counts only the four SecOC oracle IDs (0x0F sync, 0x2E4/0x131/0x344
protected) on buses 0/2, so its "0/0" can't tell "no CAN at all" from "CAN present
but different IDs/bus". This drops every filter and counts every arbitration ID on
every bus, splitting the failure into: nothing on any bus (wiring / pin-swap), vs
traffic on a bus the oracle ignores (bus mapping), vs traffic present but sync 0x0F
absent (different sync ID, or no SecOC on this car).

Read-only: no UDS session, no TX, no key or oracle writes. Shares the panda-takeover
preamble with collect_can.py by deliberate duplication.
"""
import subprocess
import time
from collections import Counter

from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor

SNIFF_SECONDS = 8.0
KNOWN_BUSES = (0, 1, 2)   # always reported, even at 0 frames, so the screenshot has a fixed shape
MAX_IDS_PER_BUS = 40      # cap the per-bus ID list so a phone screenshot stays legible

# SecOC markers highlighted on the result (checked across every bus). Sync 0x0F is
# the one the matcher can't do without; the three protected IDs are the Sienna's
# signed set. Order matches the page's display.
MARKERS = (("sync 0x0F", 0x0F), ("0x2E4", 0x2E4), ("0x131", 0x131), ("0x344", 0x344))


def _noop(**kwargs) -> None:
  pass


def summarize_counts(bus_counters, seconds, bus_maxlen=None) -> dict:
  """Build the result dict from {bus: Counter(addr -> count)}.

  Pure — no car I/O — so it is unit-testable off-device and is reused by the
  server's off-AGNOS mock to guarantee the mock and the real path share one shape.
  Buses in KNOWN_BUSES are always listed (0 frames if unseen); any extra bus that
  actually carried traffic is appended. bus_maxlen ({bus: max data length seen}), when
  given, flags buses carrying frames longer than 8 bytes as CAN-FD — a signed segment
  on an FD bus would be under-captured by classic-CAN reads.
  """
  bus_maxlen = bus_maxlen or {}
  buses = []
  total = 0
  fd_buses = []
  for bus in sorted(set(KNOWN_BUSES) | set(bus_counters)):
    counter = bus_counters.get(bus, {})
    bus_total = sum(counter.values())
    total += bus_total
    ids = sorted(counter)
    max_len = bus_maxlen.get(bus, 0)
    if max_len > 8:
      fd_buses.append(bus)
    buses.append({
      "bus": bus,
      "total": bus_total,
      "unique": len(ids),
      "ids": [f"0x{a:x}" for a in ids[:MAX_IDS_PER_BUS]],
      "truncated": len(ids) > MAX_IDS_PER_BUS,
      "max_len": max_len,
    })
  markers = []
  for label, addr in MARKERS:
    hits = sorted(bus for bus, counter in bus_counters.items() if counter.get(addr))
    markers.append({"label": label, "buses": hits})
  live = len([b for b in buses if b["total"]])
  fd_note = f" CAN-FD on bus {', '.join(map(str, fd_buses))}." if fd_buses else ""
  return {
    "status": "complete",
    "seconds": round(seconds, 1),
    "total": total,
    "buses": buses,
    "markers": markers,
    "fd_buses": fd_buses,
    "message": f"{total} frames across {live} live bus(es) in {seconds:.0f}s.{fd_note}",
  }


def sniff(progress_cb=None, seconds=SNIFF_SECONDS) -> dict:
  """Take the panda and tally every CAN frame per bus for `seconds`. Read-only.

  progress_cb, if given, is called as progress_cb(seconds=, frames=, buses=).
  Returns summarize_counts()'s dict (status "complete"); the server sets "failed"
  on an unhandled exception. Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from opendbc.car.structs import CarParams

  # Kill the manager so pandad doesn't fight for the panda (mirrors collect/dump).
  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)

  panda = TSKExtractor._connect_panda()
  panda.set_safety_mode(CarParams.SafetyModel.elm327)

  bus_counters: dict = {}
  bus_maxlen: dict = {}
  frame_total = 0
  begin = time.time()
  last_progress = begin
  cb(seconds=0.0, frames=0, buses=0)

  while time.time() - begin < seconds:
    frames = panda.can_recv()
    if not frames:
      time.sleep(0.005)
      continue
    for addr, *_, data, bus in frames:
      bus_counters.setdefault(bus, Counter())[addr] += 1
      if len(data) > bus_maxlen.get(bus, 0):
        bus_maxlen[bus] = len(data)
      frame_total += 1
    now = time.time()
    if now - last_progress >= 1.0:
      last_progress = now
      cb(seconds=now - begin, frames=frame_total, buses=len(bus_counters))

  elapsed = time.time() - begin
  cb(seconds=elapsed, frames=frame_total, buses=len(bus_counters))
  return summarize_counts(bus_counters, elapsed, bus_maxlen)
