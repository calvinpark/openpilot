import sys

from openpilot.selfdrive.ui.mici.widgets.dialog import BigConfirmationDialogV2
from openpilot.system.ui.lib.application import gui_app
from tsk.c4.ui import ScalableBigButton, Layout, ScrollableBigDialog
from tsk.common.key_file_manager import KeyFileManager


class Reboot(ScalableBigButton):
  def __init__(self):
    super().__init__(
      "Reboot to try again",
      click_callback=self.click,
      font_size=Layout.reboot_row_button_font_size,
    )

  @staticmethod
  def click():
    """Action to perform when the 'Reboot to try again' button is pressed."""
    # Build confirmation message
    key = KeyFileManager().installed_key
    if key:
      message = f"Key installed: {key}\n\n"
    else:
      message = "!!!! Key not installed.\n\n"
    message += "Reboot without changing anything?"

    # Show confirmation dialog with slider
    dialog = BigConfirmationDialogV2(
      title="Slide to reboot without changing anything",
      icon="icons_mici/settings/device/reboot.png",
      red=False,
      confirm_callback=Reboot._do_reboot
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
    """Actually perform the reboot."""
    print("Reboot confirmed - exiting to trigger reboot")
    # Do nothing - just exit, which triggers a reboot
    sys.exit(0)
