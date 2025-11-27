from openpilot.selfdrive.ui.mici.widgets.dialog import BigConfirmationDialogV2
from openpilot.system.ui.lib.application import gui_app
from tsk.c4.ui import ScalableBigButton, Layout, ScrollableBigDialog
from tsk.common.key_file_manager import KeyFileManager


class Uninstaller(ScalableBigButton):
  def __init__(self):
    super().__init__(
      "TSK Uninstaller",
      click_callback=self.click,
      font_size=Layout.tools_row_button_font_size,
    )

  @staticmethod
  def click():
    key_manager = KeyFileManager()
    key = key_manager.installed_key

    if not key:
      message = "Key not installed.\n\n" \
                "Nothing to do."
      dialog = ScrollableBigDialog(description=message)
      gui_app.set_modal_overlay(dialog)
      return

    # Show confirmation dialog with slider
    dialog = BigConfirmationDialogV2(
      title="Slide to\nuninstall the key",
      icon="icons_mici/settings/device/reboot.png",
      red=False,
      confirm_callback=Uninstaller._do_reboot
    )

    # Show informational message first
    message = f"Key installed: {key}\n\n" \
              "Uninstall?"
    info_dialog = ScrollableBigDialog(
      description=message,
      right_btn="check",
      right_btn_callback=lambda: (gui_app.set_modal_overlay(None), gui_app.set_modal_overlay(dialog))
    )
    gui_app.set_modal_overlay(info_dialog)

  @staticmethod
  def _do_reboot():
    key_manager = KeyFileManager()
    key_manager.uninstall_key()
