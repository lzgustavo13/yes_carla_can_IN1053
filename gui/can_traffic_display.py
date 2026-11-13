import datetime
import threading
from collections import deque

import can
import pygame

from can_network.network import VCAN_CHANNEL, CAN_INTERFACE


class CANTrafficDisplay:
    """
    Renders a live CAN-traffic panel (candump-style) on the right edge of the
    pygame display.  Opens its own read-only bus on *vcan0* so it never
    interferes with the main CAN_Network bus.
    """

    PANEL_WIDTH = 480
    LINE_HEIGHT = 22
    PADDING = 8
    HEADER = f"CAN Traffic  ({VCAN_CHANNEL})"
    COLOR_BG = (0, 0, 0)
    COLOR_HEADER = (0, 230, 100)
    COLOR_TEXT = (160, 255, 160)
    COLOR_DIVIDER = (0, 180, 80)

    def __init__(self, channel: str = VCAN_CHANNEL, max_messages: int = 30):
        self._messages: deque[str] = deque(maxlen=max_messages)
        self._lock = threading.Lock()
        self._active = False
        self._font = None
        self._font_size = None
        self._bus = None

        try:
            self._bus = can.Bus(interface=CAN_INTERFACE, channel=channel)
            self._active = True
        except Exception as exc:
            print(f"[CANTrafficDisplay] Could not open {channel}: {exc}")
            return

        self._thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._thread.start()

    def _recv_loop(self):
        while self._active:
            try:
                msg = self._bus.recv(timeout=1.0)
                if msg is None:
                    continue
                ts = datetime.datetime.fromtimestamp(msg.timestamp).strftime(
                    "%H:%M:%S.%f"
                )[:-3]
                data_str = " ".join(f"{b:02X}" for b in msg.data)
                line = f"{ts}  {msg.arbitration_id:03X}  [{msg.dlc}]  {data_str}"
                with self._lock:
                    self._messages.append(line)
            except can.CanOperationError:
                self._active = False
                break
            except Exception:
                self._active = False
                break

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_font(self, panel_width):
        font_size = min(18, max(10, panel_width // 28))
        if self._font is not None and self._font_size == font_size:
            return
        self._font_size = font_size
        fonts = [x for x in pygame.font.get_fonts() if "mono" in x]
        preferred = "ubuntumono"
        name = preferred if preferred in fonts else (fonts[0] if fonts else None)
        if name:
            self._font = pygame.font.Font(pygame.font.match_font(name), font_size)
        else:
            self._font = pygame.font.Font(pygame.font.get_default_font(), font_size)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def stop(self):
        self._active = False
        if self._bus:
            self._bus.shutdown()
        if hasattr(self, "_thread"):
            self._thread.join(timeout=2.0)

    def render(self, display: pygame.Surface):
        screen_w, screen_h = display.get_size()
        panel_width = min(self.PANEL_WIDTH, screen_w - screen_w // 2)
        panel_x = screen_w - panel_width
        self._init_font(panel_width)

        # Semi-transparent background
        bg = pygame.Surface((panel_width, screen_h), pygame.SRCALPHA)
        bg.fill((*self.COLOR_BG, 140))
        display.blit(bg, (panel_x, 0))

        # Header
        status = "" if self._active else "  [unavailable]"
        header_surf = self._font.render(
            self.HEADER + status, True, self.COLOR_HEADER
        )
        display.blit(header_surf, (panel_x + self.PADDING, self.PADDING))

        divider_y = self.PADDING + self.LINE_HEIGHT + 2
        pygame.draw.line(
            display,
            self.COLOR_DIVIDER,
            (panel_x, divider_y),
            (screen_w, divider_y),
            1,
        )

        if not self._active:
            return

        # Messages – most recent at the top
        with self._lock:
            snapshot = list(self._messages)

        y = divider_y + 4
        for line in reversed(snapshot):
            if y + self.LINE_HEIGHT > screen_h:
                break
            # Clip long payloads within the CAN panel instead of covering the HUD.
            surf = self._font.render(line, True, self.COLOR_TEXT)
            visible_width = panel_width - 2 * self.PADDING
            if surf.get_width() > visible_width:
                surf = surf.subsurface((0, 0, visible_width, surf.get_height()))
            display.blit(surf, (panel_x + self.PADDING, y))
            y += self.LINE_HEIGHT
