#!/usr/bin/env python3
"""File operations over the whole /cache/tsk tree: enumerate it, name a zip of it,
delete it.

Split out of tsk/web/server.py under the Hard Rule that the server is HTTP routing
only. The server still owns the transport, streaming the archive into the socket and
resetting its own in-memory state; everything that touches the filesystem lives here.

Scope is the tree rather than any one producer: it carries the CAN oracle, the
DataFlash dump, the range dumps, the preflight reports and the security-access log,
which is why this is its own module rather than a part of preflight_store.

THE INSTALLED KEY IS NOT IN THIS TREE. KeyFileManager writes /cache/params/SecOCKey,
a sibling of /cache/tsk, so delete_all() cannot reach it.
"""
import shutil
import time
from pathlib import Path

from tsk.lib import preflight_store
from tsk.lib.env import TSK_DIR


def root() -> Path:
  return Path(TSK_DIR)


def list_files() -> list:
  """Every file under the tree, sorted, deepest paths included. [] when empty."""
  try:
    return sorted(p for p in root().rglob("*") if p.is_file())
  except OSError:
    return []


def arcname(path: Path) -> str:
  """Path inside the zip, rooted at `tsk/` so an unpacked archive is self-naming."""
  return str(path.relative_to(root().parent))


def zip_name(stamp=None) -> str:
  """tsk_dumps_<ecu serial>_<stamp>.zip, dongle id when no serial was ever read.

  The ECU serial is what identifies a car across owners, so it leads. Falling back to
  the comma's dongle id keeps a downloaded archive attributable when 0xF18C never
  answered, and both are sanitised to filename-safe characters.
  """
  label = preflight_store.stored_ecu_serial()
  if label == preflight_store.UNATTRIBUTED:
    report = preflight_store.latest_report() or {}
    label = (report.get("panda") or {}).get("dongle") or preflight_store.UNATTRIBUTED
  safe = "".join(c for c in str(label) if c.isalnum() or c in "-_") or "unknown"
  return f"tsk_dumps_{safe}_{stamp or time.strftime('%Y%m%d-%H%M%S')}.zip"


def delete_all() -> bool:
  """Remove the tree and recreate it empty. True only when the tree really is empty.

  Recreated rather than left absent because launch_chffrplus.sh creates /cache/tsk
  once per boot and chowns it to comma; a delete that left it missing would make
  every later write depend on the server's own mkdir succeeding under whatever owner
  it is running as.

  THE EMPTINESS CHECK IS THE RETURN VALUE. rmtree(ignore_errors=True) swallows
  per-file failures, so without it a partial delete returned True and the caller
  reset every in-memory state to empty while files were still on disk. Anything
  root-owned that ever appears under the tree hits exactly that, since the server
  runs as comma. Re-reading the tree also covers failure modes ignore_errors hides
  that are not enumerated here.
  """
  target = root()
  try:
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True, exist_ok=True)
  except OSError:
    return False
  return not list_files()
