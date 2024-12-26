import sys
from pathlib import Path

from PyQt5.QtCore import Qt, QTimer, QPoint
from PyQt5.QtGui import QPainter, QTextCursor, QTextCharFormat, QColor, QFont
from PyQt5.QtWidgets import (
  QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QSizePolicy, QTextEdit, QLabel
)

from openpilot.selfdrive.ui.qt.python_helpers import set_main_window

BUTTON_MIN_WIDTH = 80
BUTTON_MIN_HEIGHT = 200
INPUT_BOX_WIDTH = 1500
INPUT_BOX_HEIGHT = 105
MAX_INPUT_LENGTH = 32

DARK_COLORS = ["#6A0DAD", "#2F4F4F", "#556B2F", "#8B0000", "#1874CD", "#006400"]
HEX_ALPHABET = "0123456789abcdef"

GLOBAL_STYLESHEET = """
QWidget { background-color: black; color: gray; font-size: 70px; }
QPushButton { font-size: 70px; color: gray; border-radius: 10px; }
QTextEdit { font-size: 70px; color: #dddddd; background-color: #0F0F0F; border: 2px solid #AAAAAA; border-radius: 10px; padding: 10px; }
QLabel { font-size: 70px; color: gray; }
"""

BUTTON_STYLESHEET = """
QPushButton { font-size: 70px; border: 3px solid #AAAAAA; border-radius: 10px; margin: 5px; padding: 5px; background-color: #444444; color: gray; }
QPushButton:pressed { background-color: #666666; }
"""

BACKSPACE_CHAR = "⌫"


class FullScreenApp(QWidget):
  def __init__(self):
    super().__init__()
    self.remaining_seconds = 3
    self.overlay_visible = False
    self.full_input = False
    self.current_installed_key = "Missing"
    self.colors = DARK_COLORS

    self.init_timers()
    default_key = self.read_persist_key()
    self.init_ui(default_key)
    self.init_key_check_timer()

  def init_key_check_timer(self):
    self.key_check_timer = QTimer(self)
    self.key_check_timer.setInterval(1000)
    self.key_check_timer.timeout.connect(self.check_secoc_key_file)
    self.key_check_timer.start()

  def check_secoc_key_file(self):
    key_file = Path("/data/params/d/SecOCKey")
    if not key_file.exists():
      if self.current_installed_key != "Missing":
        self.current_installed_key = "Missing"
        self.update_installed_key_label()
      return
    try:
      raw_content = key_file.read_text().strip()
      if len(raw_content) == MAX_INPUT_LENGTH and all(c in HEX_ALPHABET for c in raw_content.lower()):
        if self.current_installed_key != raw_content:
          self.current_installed_key = raw_content
          self.update_installed_key_label()
      else:
        invalid_text = f"Invalid ({raw_content})"
        if self.current_installed_key != invalid_text:
          self.current_installed_key = invalid_text
          self.update_installed_key_label()
    except Exception as e:
      err_text = f"Invalid ({e})"
      if self.current_installed_key != err_text:
        self.current_installed_key = err_text
        self.update_installed_key_label()

  def update_installed_key_label(self):
    self.installed_key_label.setText(f"Installed key: {self.current_installed_key}")

  def read_persist_key(self):
    key_path = Path("/persist/tsk/key")
    return key_path.read_text().strip() if key_path.exists() and len(key_path.read_text().strip()) == MAX_INPUT_LENGTH and all(c in HEX_ALPHABET for c in key_path.read_text().strip().lower()) else ""

  def init_ui(self, default_text):
    self.exit_button = QPushButton("👆🕔🚪")
    self.exit_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    self.exit_button.setMinimumSize(150, 100)
    self.exit_button.setStyleSheet("font-size: 100px;")
    self.exit_button.pressed.connect(self.start_exit_timer)
    self.exit_button.released.connect(self.stop_exit_timer)

    self.installed_key_label = QLabel("Installed key: Missing")
    self.installed_key_label.setStyleSheet("font-size: 65px;")

    self.input_box = QTextEdit(self)
    self.input_box.setPlaceholderText("Type your Toyota Security Key")
    self.input_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    self.input_box.setFixedWidth(INPUT_BOX_WIDTH)
    self.input_box.setFixedHeight(INPUT_BOX_HEIGHT)
    self.input_box.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    self.input_box.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    self.input_box.setAcceptRichText(True)
    self.input_box.installEventFilter(self)
    self.input_box.setText(default_text)
    self.input_box.textChanged.connect(self.update_text_color)

    self.input_label = QLabel(f"{MAX_INPUT_LENGTH} characters remaining")
    self.input_label.setAlignment(Qt.AlignCenter)

    self.save_button = QPushButton("Install this key")
    self.save_button.setStyleSheet(BUTTON_STYLESHEET)
    self.save_button.setVisible(False)
    self.save_button.clicked.connect(self.save_key)

    self.success_label = QLabel("Success!")
    self.success_label.setAlignment(Qt.AlignCenter)
    self.success_label.setVisible(False)

    self.hex_buttons_row1 = self.create_buttons([str(x) for x in range(1, 10)] + ["0"])  # 1-9 then 0
    self.hex_buttons_row2 = self.create_buttons(list("abcdef") + [BACKSPACE_CHAR])
    self.setup_layout()
    self.update_text_color()

  def create_buttons(self, chars):
    buttons = []
    for ch in chars:
      btn = QPushButton(ch)
      btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
      btn.setMinimumSize(BUTTON_MIN_WIDTH, BUTTON_MIN_HEIGHT)
      btn.setStyleSheet(BUTTON_STYLESHEET)
      if ch == BACKSPACE_CHAR:
        btn.clicked.connect(self.perform_backspace)
      else:
        btn.clicked.connect(lambda checked, c=ch: self.on_button_clicked(c))
      buttons.append(btn)
    return buttons

  def on_button_clicked(self, char):
    cursor = self.input_box.textCursor()
    cursor.movePosition(QTextCursor.End)
    self.input_box.setTextCursor(cursor)
    if len(self.input_box.toPlainText()) < MAX_INPUT_LENGTH:
      self.insert_colored_text(char, len(self.input_box.toPlainText()))

  def insert_colored_text(self, char, position):
    cursor = self.input_box.textCursor()
    fmt = QTextCharFormat()
    fmt.setForeground(QColor(self.colors[(position // 4) % len(self.colors)]))
    cursor.insertText(char, fmt)

  def perform_backspace(self):
    cursor = self.input_box.textCursor()
    cursor.movePosition(QTextCursor.End)
    self.input_box.setTextCursor(cursor)
    if self.input_box.toPlainText():
      cursor.deletePreviousChar()
      self.update_text_color()

  def update_text_color(self):
    text = self.input_box.toPlainText()
    if len(text) > MAX_INPUT_LENGTH:
      text = text[:MAX_INPUT_LENGTH]
      self.input_box.blockSignals(True)
      self.input_box.setText(text)
      self.input_box.blockSignals(False)

    self.full_input = len(text) == MAX_INPUT_LENGTH
    self.input_label.setVisible(not self.full_input)
    self.save_button.setVisible(self.full_input)
    self.success_label.setVisible(False)
    if not self.full_input:
      self.input_label.setText(f"{MAX_INPUT_LENGTH - len(text)} characters remaining")

    self.reapply_coloring(text)

  def reapply_coloring(self, text):
    self.input_box.blockSignals(True)
    self.input_box.clear()
    for i, ch in enumerate(text):
      self.insert_colored_text(ch, i)
    self.input_box.blockSignals(False)

  def save_key(self):
    key = self.input_box.toPlainText()
    if len(key) == MAX_INPUT_LENGTH:
      try:
        for p in [Path("/data/params/d/SecOCKey"), Path("/persist/tsk/key")]:
          p.parent.mkdir(parents=True, exist_ok=True)
          p.write_text(key)
        self.save_button.setVisible(False)
        self.success_label.setVisible(True)
      except Exception as e:
        self.input_label.setText(f"Error: {e}")

  def toggle_interface(self, visible):
    self.input_box.setVisible(visible)
    self.input_label.setVisible(visible and not self.full_input)
    self.save_button.setVisible(visible and self.full_input and not self.overlay_visible)
    self.success_label.setVisible(visible and self.success_label.isVisible())
    self.installed_key_label.setVisible(visible and not self.overlay_visible)
    for btn in (self.hex_buttons_row1 + self.hex_buttons_row2):
      btn.setVisible(visible and not self.overlay_visible)

  def setup_layout(self):
    top_layout = QHBoxLayout()
    top_layout.addStretch(1)
    top_layout.addWidget(self.exit_button)

    installed_key_layout = QHBoxLayout()
    installed_key_layout.addWidget(self.installed_key_label, alignment=Qt.AlignCenter)

    center_layout = QVBoxLayout()
    center_layout.addStretch(1)
    center_layout.addLayout(installed_key_layout)
    center_layout.addWidget(self.input_box, alignment=Qt.AlignCenter)
    center_layout.addWidget(self.input_label, alignment=Qt.AlignCenter)
    center_layout.addWidget(self.save_button, alignment=Qt.AlignCenter)
    center_layout.addWidget(self.success_label, alignment=Qt.AlignCenter)
    center_layout.addStretch(1)

    row1_layout = QHBoxLayout()
    for btn in self.hex_buttons_row1:
      row1_layout.addWidget(btn)

    row2_layout = QHBoxLayout()
    row2_layout.setContentsMargins(0, 20, 0, 0)
    for btn in self.hex_buttons_row2:
      row2_layout.addWidget(btn)

    hex_layout = QVBoxLayout()
    hex_layout.addLayout(row1_layout)
    hex_layout.addLayout(row2_layout)

    main_layout = QVBoxLayout()
    main_layout.addLayout(top_layout)
    main_layout.addLayout(center_layout)
    main_layout.addLayout(hex_layout)
    main_layout.setContentsMargins(20, 20, 20, 20)
    self.setLayout(main_layout)

  def init_timers(self):
    self.exit_timer = QTimer(self)
    self.exit_timer.setSingleShot(True)
    self.exit_timer.timeout.connect(self.quit_app)

    self.press_timer = QTimer(self)
    self.press_timer.setSingleShot(True)
    self.press_timer.timeout.connect(self.quit_app)

    self.countdown_timer = QTimer(self)
    self.countdown_timer.setInterval(1000)
    self.countdown_timer.timeout.connect(self.update_countdown)

  def start_exit_timer(self):
    self.press_timer.start(3000)
    self.overlay_visible = True
    self.countdown_timer.start()
    self.remaining_seconds = 3
    self.toggle_interface(False)
    self.update()

  def stop_exit_timer(self):
    self.press_timer.stop()
    self.countdown_timer.stop()
    self.overlay_visible = False
    self.toggle_interface(True)
    self.update()

  def quit_app(self):
    QApplication.instance().quit()

  def update_countdown(self):
    self.remaining_seconds -= 1
    if self.remaining_seconds > 0:
      self.update()

  def eventFilter(self, source, event):
    if source == self.input_box and event.type() == event.KeyPress:
      if event.key() in (Qt.Key_Return, Qt.Key_Enter):
        return True
      elif event.key() == Qt.Key_Backspace:
        self.perform_backspace()
        return True
    return super().eventFilter(source, event)

  def paintEvent(self, event):
    super().paintEvent(event)
    if self.overlay_visible:
      painter = QPainter(self)
      painter.fillRect(self.rect(), Qt.black)
      painter.setPen(Qt.gray)
      painter.setFont(QFont("", 150))
      msg = f"🚪🏃 {self.remaining_seconds}"
      fm = painter.fontMetrics()
      rect = fm.boundingRect(msg)
      x = (self.width() - rect.width()) // 2
      y = (self.height() - rect.height()) // 2 + fm.ascent()
      painter.drawText(QPoint(x, y), msg)


def main():
  app = QApplication(sys.argv)
  app.setStyleSheet(GLOBAL_STYLESHEET)
  window = FullScreenApp()
  set_main_window(window)
  keep_alive_timer = QTimer()
  keep_alive_timer.timeout.connect(lambda: None)
  keep_alive_timer.start(100)
  sys.exit(app.exec_())


if __name__ == "__main__":
  main()
