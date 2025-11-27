import shutil
import sys

from openpilot.selfdrive.ui.mici.widgets.dialog import BigConfirmationDialogV2
from openpilot.system.ui.lib.application import gui_app
from tsk.c4.ui import ScalableBigButton, Layout, ScrollableBigDialog
from tsk.common.env import OPENPILOT_DIR, RECOMMENDED_OP_DIR, ALTERNATE_OP_DIR, ALTERNATE_OP_USER, ALTERNATE_OP_BRANCH
from tsk.common.key_file_manager import KeyFileManager


class Alternate(ScalableBigButton):
  def __init__(self):
    super().__init__(
      f"Install {ALTERNATE_OP_USER}/ {ALTERNATE_OP_BRANCH}",
      click_callback=self.click,
      font_size=Layout.reboot_row_button_font_size,
    )

  @staticmethod
  def click():
    # Build confirmation message
    key = KeyFileManager().installed_key
    if key:
      message = f"Key installed: {key}\n\n"
    else:
      message = "!!!! Key not installed.\n" \
                "!!!! Comma can't drive your car.\n\n"
    message += f"Reboot and install {ALTERNATE_OP_USER}/{ALTERNATE_OP_BRANCH}?"

    # Show confirmation dialog with slider
    dialog = BigConfirmationDialogV2(
      title=f"Slide to install\n{ALTERNATE_OP_USER}/ {ALTERNATE_OP_BRANCH}",
      icon="icons_mici/settings/device/reboot.png",
      red=False,
      confirm_callback=Alternate._do_reboot
    )

    # Show informational message first
    info_dialog = ScrollableBigDialog(
      description=message,
      right_btn="check",
      right_btn_callback=lambda: (gui_app.set_modal_overlay(None), gui_app.set_modal_overlay(dialog))
    )
    gui_app.set_modal_overlay(info_dialog)

  @staticmethod
  def _do_reboot():
    # Remove /data/openpilot since it won't be used
    shutil.rmtree(OPENPILOT_DIR, ignore_errors=True)
    print(f"Removed {OPENPILOT_DIR}")

    # Remove /data/tsk-recommended since it won't be used
    shutil.rmtree(RECOMMENDED_OP_DIR, ignore_errors=True)
    print(f"Removed {RECOMMENDED_OP_DIR}")

    # Move /data/tsk-alternate to /data/openpilot
    shutil.move(ALTERNATE_OP_DIR, OPENPILOT_DIR)
    print(f"Moved {ALTERNATE_OP_DIR} to {OPENPILOT_DIR}")

    sys.exit(0)
