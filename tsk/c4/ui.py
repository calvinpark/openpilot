from typing import Callable

import pyray as rl

from openpilot.common.filter_simple import BounceFilter
from openpilot.selfdrive.ui.mici.widgets.dialog import BigDialogBase
from openpilot.system.ui.lib.application import gui_app, FontWeight, MouseEvent
from openpilot.system.ui.lib.text_measure import measure_text_cached
from openpilot.system.ui.lib.wrap_text import wrap_text
from openpilot.system.ui.widgets import Widget, DialogResult
from openpilot.system.ui.widgets.label import MiciLabel, UnifiedLabel
from openpilot.system.ui.widgets.scroller import Scroller


class Layout:
  # Button dimensions
  button_width = 240
  button_height = 140

  # Font sizes
  tools_row_button_font_size = 40
  reboot_row_button_font_size = 35

  # Scroller configuration
  scroller_spacing = 10
  scroller_padding = 10

  # Banner
  banner_height = 50


class ScalableBigButton(Widget):
  """
  Button that uses BigButton graphics but scales to any size.
  """
  def __init__(self,
               text: str,
               click_callback: Callable = None,
               font_size: int = Layout.tools_row_button_font_size,
               text_offset: tuple[int, int] = (15, 30),
               button_width = Layout.button_width,
               button_height = Layout.button_height,
               ):
    super().__init__()
    self._text = text
    self._font_size = font_size
    self._text_offset = text_offset  # (x, y) offset from top-left of button
    self.set_click_callback(click_callback)

    # Load BigButton textures
    self._txt_default_bg = gui_app.texture("icons_mici/buttons/button_rectangle.png", 402, 180)
    self._txt_hover_bg = gui_app.texture("icons_mici/buttons/button_rectangle_hover.png", 402, 180)

    # Scale animation
    self._scale_filter = BounceFilter(1.0, 0.1, 1 / gui_app.target_fps)

    # Label for text
    self._label = MiciLabel(
      text,
      font_size=font_size,
      font_weight=FontWeight.DISPLAY,
      color=rl.WHITE,
      alignment_vertical=rl.GuiTextAlignmentVertical.TEXT_ALIGN_MIDDLE,
      wrap_text=True
    )

    self.set_rect(rl.Rectangle(0, 0, button_width, button_height))

  def _render(self, rect: rl.Rectangle):
    """Render the button with scaled BigButton graphics."""
    # Choose texture based on press state
    txt_bg = self._txt_hover_bg if self.is_pressed else self._txt_default_bg

    # Scale animation
    scale = self._scale_filter.update(1.07 if self.is_pressed else 1.0)

    # Calculate scaled position (center the scaled button)
    scaled_width = rect.width * scale
    scaled_height = rect.height * scale
    btn_x = rect.x + (rect.width - scaled_width) / 2
    btn_y = rect.y + (rect.height - scaled_height) / 2

    # Draw background texture scaled to button size
    source_rect = rl.Rectangle(0, 0, self._txt_default_bg.width, self._txt_default_bg.height)
    dest_rect = rl.Rectangle(btn_x, btn_y, scaled_width, scaled_height)
    rl.draw_texture_pro(txt_bg, source_rect, dest_rect, rl.Vector2(0, 0), 0, rl.WHITE)

    # Draw text at specified offset from button top-left
    text_x = rect.x + self._text_offset[0]
    text_y = rect.y + self._text_offset[1]
    self._label.set_position(text_x, text_y)
    self._label.set_width(int(rect.width - self._text_offset[0] * 2))
    self._label.render()

    return True


class ScrollableBigDialog(BigDialogBase):
  """
  A BigDialog variant that supports scrolling for long text content.

  Features:
  - Optional title (no space wasted if title is empty string or None)
  - Configurable alignment for title and description (left or center)
  - Configurable font sizes for title and description
  - Scrollable description area

  Usage:
    dialog = ScrollableBigDialog(
      title="Title",
      description="Very long text that needs scrolling...",
      title_font_size=50,
      title_alignment=rl.GuiTextAlignment.TEXT_ALIGN_CENTER,
      desc_font_size=30,
      desc_alignment=rl.GuiTextAlignment.TEXT_ALIGN_LEFT
    )
    gui_app.set_modal_overlay(dialog)
  """
  PADDING = 20

  def __init__(self,
               title: str = "",
               description: str = "",
               right_btn: str | None = None,
               right_btn_callback: Callable | None = None,
               title_font_size: int = 50,
               title_alignment: int = rl.GuiTextAlignment.TEXT_ALIGN_CENTER,
               desc_font_size: int = 50,
               desc_alignment: int = rl.GuiTextAlignment.TEXT_ALIGN_LEFT,
               scroll_to_bottom: bool = False):
    super().__init__(right_btn, right_btn_callback)
    self._title = title
    self._description = description
    self._title_font_size = title_font_size
    self._title_alignment = title_alignment
    self._desc_font_size = desc_font_size
    self._desc_alignment = desc_alignment
    self._scroll_to_bottom = scroll_to_bottom
    self._initial_scroll_done = False

    # Create label for description text
    max_width = self._rect.width - self.PADDING * 2
    if self._right_btn:
      max_width -= self._right_btn._rect.width

    self._desc_label = UnifiedLabel(
      description,
      font_size=desc_font_size,
      text_color=rl.WHITE,
      font_weight=FontWeight.MEDIUM,
      alignment=desc_alignment
    )

    # Create scroller for the description with scroll indicator
    self._scroller = Scroller(
      [self._desc_label],
      horizontal=False,
      snap_items=False,
      spacing=0,
      pad_start=10,
      pad_end=10
    )
    # Load scroll indicator texture
    self._txt_scroll_indicator = gui_app.texture("icons_mici/settings/vertical_scroll_indicator.png", 40, 80)

  def _handle_mouse_event(self, mouse_event: MouseEvent) -> None:
    """
    Override NavWidget's mouse event handling to only allow dismiss when scroller is at top.
    This fixes the issue where swiping down dismisses the dialog even when scrolled down.
    """
    # Only check scroll position when gesture starts (on press), not during drag
    # This matches NavWidget's behavior and prevents mid-gesture blocking
    if mouse_event.left_pressed:
      # Check if scroller is at top position (offset >= -20 allows for some tolerance)
      scroller_at_top = self._scroller.scroll_panel.get_offset() >= -20

      # Temporarily disable back gesture if not at top
      if not scroller_at_top:
        # Store original state and disable
        original_back_enabled = self._back_enabled
        self._back_enabled = False

        # Call parent's mouse event handler with back disabled
        super()._handle_mouse_event(mouse_event)

        # Restore original state
        self._back_enabled = original_back_enabled
        return  # Don't call super again

    # For all other events, or if scroller is at top, allow normal handling
    super()._handle_mouse_event(mouse_event)

  def _render(self, _) -> DialogResult:
    super()._render(_)

    # Calculate available width
    max_width = self._rect.width - self.PADDING * 2
    if self._right_btn:
      max_width -= self._right_btn._rect.width

    # Draw title (if provided and not empty)
    title_bottom = self._rect.y + self.PADDING
    if self._title:
      title_wrapped = '\n'.join(wrap_text(gui_app.font(FontWeight.BOLD), self._title, self._title_font_size, int(max_width)))
      title_size = measure_text_cached(gui_app.font(FontWeight.BOLD), title_wrapped, self._title_font_size)
      title_rect = rl.Rectangle(
        int(self._rect.x + self.PADDING),
        int(self._rect.y + self.PADDING),
        int(max_width),
        int(title_size.y)
      )

      from openpilot.system.ui.widgets.label import gui_label
      gui_label(title_rect, title_wrapped, self._title_font_size, font_weight=FontWeight.BOLD,
                alignment=self._title_alignment)

      title_bottom = title_rect.y + title_rect.height + self.PADDING

    # Calculate scroller area (below title, full remaining height)
    scroller_rect = rl.Rectangle(
      int(self._rect.x + self.PADDING),
      int(title_bottom),
      int(max_width),
      int(self._rect.y + self._rect.height - title_bottom - self.PADDING)
    )

    # Update label width for proper text wrapping
    self._desc_label.set_max_width(int(max_width))

    # Check if content is scrollable
    content_height = self._desc_label.get_content_height(int(max_width))
    is_scrollable = content_height > scroller_rect.height

    # Disable scrolling if content fits in viewport
    self._scroller.set_scrolling_enabled(is_scrollable)

    # Scroll to bottom on first render if flag is set
    if self._scroll_to_bottom and not self._initial_scroll_done and is_scrollable:
      scrollable_height = content_height - scroller_rect.height
      self._scroller.scroll_panel.set_offset(-scrollable_height)
      self._initial_scroll_done = True

    # Render the scroller
    self._scroller.render(scroller_rect)

    # Draw scroll indicator if content is scrollable
    if is_scrollable:
      # Calculate scroll position
      scroll_offset = self._scroller.scroll_panel.get_offset()
      scrollable_height = content_height - scroller_rect.height

      # Calculate indicator position (proportional to scroll position)
      indicator_travel = scroller_rect.height - self._txt_scroll_indicator.height
      scroll_progress = -scroll_offset / scrollable_height if scrollable_height > 0 else 0
      scroll_progress = max(0, min(1, scroll_progress))  # Clamp to [0, 1]

      indicator_y = scroller_rect.y + scroll_progress * indicator_travel
      # Position completely flush against the dialog's right edge
      indicator_x = self._rect.x + self._rect.width - self._txt_scroll_indicator.width

      # Draw mirrored (flipped horizontally) on the right side
      source_rect = rl.Rectangle(0, 0, -self._txt_scroll_indicator.width, self._txt_scroll_indicator.height)
      dest_rect = rl.Rectangle(indicator_x, indicator_y, self._txt_scroll_indicator.width, self._txt_scroll_indicator.height)
      rl.draw_texture_pro(self._txt_scroll_indicator, source_rect, dest_rect, rl.Vector2(0, 0), 0, rl.WHITE)

    return self._ret
