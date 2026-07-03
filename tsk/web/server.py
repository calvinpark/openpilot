#!/usr/bin/env python3
import json
import mimetypes
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from tsk.lib.env import is_agnos, setup
from tsk.lib.extractor import NotAGNOSError, RetryError, TSKExtractor
from tsk.lib.key_file_manager import KeyFileManager, format_key
from tsk.lib.reboot_manager import REBOOT_ACTIONS, RebootManager


HOST = "0.0.0.0"
PORT = 11111
ASSET_DIR = Path(__file__).resolve().with_name("static")
OFFROAD_ALERT_PARAM = "Offroad_NoFirmware"
OFFROAD_ALERT_INTERVAL = 5.0

last_alert_url: str | None = None
extractor_lock = threading.Lock()


def append_address(addresses: list[str], ip: str) -> None:
  if ip and not ip.startswith("127.") and ip not in addresses:
    addresses.append(ip)


def get_ipv4_addresses() -> list[str]:
  addresses: list[str] = []

  try:
    output = subprocess.check_output(
      ["ip", "-o", "-4", "route", "get", "1.1.1.1"],
      encoding="utf-8",
      stderr=subprocess.DEVNULL,
      timeout=1.0,
    )
    parts = output.split()
    if "src" in parts:
      append_address(addresses, parts[parts.index("src") + 1])
  except (OSError, subprocess.SubprocessError, TimeoutError):
    pass

  try:
    for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
      append_address(addresses, info[4][0])
  except OSError:
    pass

  # AGNOS devices have the `ip` utility, and it tends to be more accurate than
  # hostname lookups for hotspot and garage Wi-Fi testing.
  try:
    output = subprocess.check_output(
      ["ip", "-o", "-4", "addr", "show", "scope", "global"],
      encoding="utf-8",
      stderr=subprocess.DEVNULL,
      timeout=1.0,
    )
    for line in output.splitlines():
      parts = line.split()
      if "inet" not in parts:
        continue

      cidr = parts[parts.index("inet") + 1]
      append_address(addresses, cidr.split("/", 1)[0])
  except (OSError, subprocess.SubprocessError, TimeoutError):
    pass

  return addresses


def get_tsk_url() -> str | None:
  addresses = get_ipv4_addresses()
  return f"http://{addresses[0]}:{PORT}" if addresses else None


def get_params_dir() -> Path:
  params_root = Path(os.getenv("PARAMS_ROOT", "/data/params"))
  params_prefix = os.getenv("OPENPILOT_PREFIX", "d") or "d"
  return params_root / params_prefix


def get_reboot_actions_payload() -> dict:
  reboot_manager = RebootManager()
  payload = {
    "is_agnos": is_agnos(),
    "dry_run": not reboot_manager.is_agnos,
  }
  payload.update(reboot_manager.actions_payload())
  return payload


def run_reboot_action(action: str) -> tuple[HTTPStatus, dict]:
  if action not in REBOOT_ACTIONS:
    return HTTPStatus.BAD_REQUEST, {
      "ok": False,
      "error": "bad_action",
      "title": "Unknown action",
      "message": f"Unknown reboot action: {action}",
      **RebootManager.key_status_payload(),
    }

  try:
    return HTTPStatus.OK, RebootManager().execute(action)
  except Exception as e:
    return HTTPStatus.INTERNAL_SERVER_ERROR, {
      "ok": False,
      "error": "unexpected",
      "title": "Unexpected error",
      "message": str(e),
      "traceback": traceback.format_exc(),
      **RebootManager.key_status_payload(),
    }


def write_offroad_alert(url: str | None) -> bool:
  params_dir = get_params_dir()
  if not params_dir.exists():
    return False

  alert_path = params_dir / OFFROAD_ALERT_PARAM
  if url is None:
    try:
      alert_path.unlink()
    except FileNotFoundError:
      pass
    return True

  payload = json.dumps({"text": "%1", "severity": 0, "extra": url}, sort_keys=True)
  tmp_path = params_dir / f".tmp_{OFFROAD_ALERT_PARAM}_{os.getpid()}"

  with open(tmp_path, "w", encoding="utf-8") as f:
    f.write(payload)
    f.flush()
    os.fsync(f.fileno())

  os.replace(tmp_path, alert_path)

  try:
    dir_fd = os.open(params_dir, os.O_RDONLY)
    try:
      os.fsync(dir_fd)
    finally:
      os.close(dir_fd)
  except OSError:
    pass

  return True


def update_offroad_alert() -> None:
  global last_alert_url

  url = get_tsk_url()
  if url == last_alert_url:
    return

  try:
    if write_offroad_alert(url):
      last_alert_url = url
  except OSError as e:
    print(f"TSK Manager Web could not update offroad alert: {e}", flush=True)


def offroad_alert_loop() -> None:
  while True:
    update_offroad_alert()
    time.sleep(OFFROAD_ALERT_INTERVAL)


def resolve_asset(path: str) -> Path | None:
  relative_path = "index.html" if path in ("", "/") else unquote(path).lstrip("/")
  if relative_path.endswith("/"):
    relative_path += "index.html"

  relative = Path(relative_path)
  if relative.is_absolute() or ".." in relative.parts:
    return None

  candidate = (ASSET_DIR / relative).resolve()
  try:
    candidate.relative_to(ASSET_DIR.resolve())
  except ValueError:
    return None

  if candidate.is_file():
    return candidate

  return None


def content_type_for(path: Path) -> str:
  content_type, _ = mimetypes.guess_type(path.name)
  content_type = content_type or "application/octet-stream"
  if content_type.startswith("text/") or content_type in ("application/javascript", "application/json"):
    content_type += "; charset=utf-8"
  return content_type


DRY_RUN_FAKE_KEY = "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"
dry_run_counter = 0


class TSKWebHandler(BaseHTTPRequestHandler):
  server_version = "TSKWeb/0.1"

  def _send_extract_dry_run(self) -> None:
    global dry_run_counter
    scenario = dry_run_counter % 3
    dry_run_counter += 1

    if scenario == 0:
      KeyFileManager().install_key(DRY_RUN_FAKE_KEY)
      self._send_json({
        "ok": True,
        "key": DRY_RUN_FAKE_KEY,
        "message": f"Success!\n\nThis is your key:\n{format_key(DRY_RUN_FAKE_KEY)}\n\nTake a screenshot now.",
      })
    elif scenario == 1:
      self._send_json({
        "ok": False,
        "message": "boardd is not running.\n\nTry again. If the problem persists, turn off the car, "
                   "put it back into 'Not Ready to Drive' mode, and then try again.",
      }, status=HTTPStatus.CONFLICT)
    else:
      self._send_json({
        "ok": False,
        "message": (
          "UDS request timed out\n\n"
          "Traceback (most recent call last):\n"
          '  File "/data/openpilot/tsk/lib/extractor.py", line 384, in run\n'
          "    secoc_key = cls.hack()\n"
          '  File "/data/openpilot/tsk/lib/extractor.py", line 241, in hack\n'
          "    seed = cls._security_access(panda)\n"
          '  File "/data/openpilot/tsk/lib/extractor.py", line 152, in _security_access\n'
          "    resp = cls._uds_request(panda, service=0x27, subfunction=0x01)\n"
          '  File "/data/openpilot/tsk/lib/extractor.py", line 113, in _uds_request\n'
          "    raise RetryError(f\"UDS request timed out\")\n"
          "tsk.lib.extractor.RetryError: UDS request timed out\n\n"
          "!!!! Unexpected error. Please take a screenshot, post it on #toyota-security, and ping @calvinspark\n"
        ),
      }, status=HTTPStatus.INTERNAL_SERVER_ERROR)

  def do_GET(self) -> None:
    self._handle_request(send_body=True)

  def do_HEAD(self) -> None:
    self._handle_request(send_body=False)

  def do_POST(self) -> None:
    path = urlparse(self.path).path

    if path == "/api/extract":
      if not extractor_lock.acquire(blocking=False):
        self._send_json({
          "ok": False,
          "message": "Extractor is already running.",
        }, status=HTTPStatus.CONFLICT)
        return

      try:
        secoc_key = TSKExtractor.hack()
        KeyFileManager().install_key(secoc_key)
        self._send_json({
          "ok": True,
          "key": secoc_key,
          "message": f"Success!\n\nThis is your key:\n{format_key(secoc_key)}\n\nTake a screenshot now.",
        })
      except NotAGNOSError:
        self._send_extract_dry_run()
        return
      except Exception as e:
        msg = str(e)
        tb = traceback.format_exc()
        self._send_json({
          "ok": False,
          "message": f"{msg}\n\n{tb}",
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      finally:
        extractor_lock.release()
      return

    if path == "/api/uninstall":
      try:
        key_manager = KeyFileManager()
        key_was_installed = key_manager.installed_key is not None
        key_manager.uninstall_key()
        self._send_json({
          "ok": True,
          "title": "Key removed" if key_was_installed else "Key not installed",
          "message": "Installed key removed." if key_was_installed else "Nothing to remove.",
          **RebootManager.key_status_payload(),
        })
      except Exception as e:
        self._send_json({
          "ok": False,
          "error": "unexpected",
          "title": "Unexpected error",
          "message": str(e),
          "traceback": traceback.format_exc(),
          **RebootManager.key_status_payload(),
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      return

    if path == "/api/reboot":
      try:
        request = self._read_json_body()
        status, payload = run_reboot_action(str(request.get("action", "")))
        self._send_json(payload, status=status)
      except Exception as e:
        self._send_json({
          "ok": False,
          "error": "unexpected",
          "title": "Unexpected error",
          "message": str(e),
          "traceback": traceback.format_exc(),
          **RebootManager.key_status_payload(),
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      return

    self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

  def _handle_request(self, send_body: bool) -> None:
    path = urlparse(self.path).path

    if path == "/api/health":
      self._send_json({
        "status": "ok",
        "service": "tsk_web",
        "host": HOST,
        "port": PORT,
        "url": get_tsk_url(),
        "addresses": get_ipv4_addresses(),
        "asset_dir": str(ASSET_DIR),
        "dry_run": not is_agnos(),
        "is_agnos": is_agnos(),
      }, send_body=send_body)
      return

    if path == "/api/status":
      self._send_json(RebootManager.key_status_payload(), send_body=send_body)
      return

    if path == "/api/reboot":
      try:
        self._send_json(get_reboot_actions_payload(), send_body=send_body)
      except Exception as e:
        self._send_json({
          "ok": False,
          "error": "unexpected",
          "title": "Unexpected error",
          "message": str(e),
          "traceback": traceback.format_exc(),
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR, send_body=send_body)
      return

    if path == "/favicon.ico":
      self.send_response(HTTPStatus.NO_CONTENT)
      self.end_headers()
      return

    asset = resolve_asset(path)
    if asset is not None:
      self._send_bytes(HTTPStatus.OK, content_type_for(asset), asset.read_bytes(), send_body=send_body)
      return

    self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND, send_body=send_body)

  def _send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK, send_body: bool = True) -> None:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    self._send_bytes(status, "application/json; charset=utf-8", body, send_body=send_body)

  def _read_json_body(self) -> dict:
    length = int(self.headers.get("Content-Length", "0") or "0")
    if length <= 0:
      return {}
    raw_body = self.rfile.read(length)
    if not raw_body:
      return {}
    return json.loads(raw_body.decode("utf-8"))

  def _send_bytes(self, status: HTTPStatus, content_type: str, body: bytes, send_body: bool = True) -> None:
    self.send_response(status)
    self.send_header("Content-Type", content_type)
    self.send_header("Content-Length", str(len(body)))
    self.send_header("Cache-Control", "no-store")
    self.end_headers()
    if send_body:
      self.wfile.write(body)

  def log_message(self, fmt: str, *args: object) -> None:
    return


class TSKWebServer(ThreadingHTTPServer):
  allow_reuse_address = True
  daemon_threads = True


def main() -> None:
  setup()
  update_offroad_alert()
  threading.Thread(target=offroad_alert_loop, name="tsk_offroad_alert", daemon=True).start()

  server = TSKWebServer((HOST, PORT), TSKWebHandler)
  print(f"TSK Manager Web listening on http://{HOST}:{PORT}", flush=True)
  for ip in get_ipv4_addresses():
    print(f"TSK Manager Web detected address: http://{ip}:{PORT}", flush=True)

  try:
    server.serve_forever()
  except KeyboardInterrupt:
    pass
  finally:
    server.server_close()


if __name__ == "__main__":
  main()
