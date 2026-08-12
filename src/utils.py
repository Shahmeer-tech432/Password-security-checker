"""
Password Security Analyzer - Utilities & Clipboard Manager

Provides safe clipboard interactions with optional automatic timeout clearing
for enhanced privacy protection.
"""

import threading
import time
from typing import Callable, Optional


class ClipboardManager:
    """
    Manages clipboard copy operations with optional delayed auto-clearing.
    """

    def __init__(self, tk_root=None, auto_clear_seconds: int = 30):
        """
        Args:
            tk_root: Root Tkinter instance for clipboard access.
            auto_clear_seconds: Time in seconds before copied password is cleared from clipboard.
        """
        self.root = tk_root
        self.auto_clear_seconds = auto_clear_seconds
        self._timer: Optional[threading.Timer] = None

    def copy_to_clipboard(self, text: str, callback_notify: Optional[Callable[[str], None]] = None) -> bool:
        """
        Copies text to system clipboard and schedules automatic clearing.

        Args:
            text: Text string to copy.
            callback_notify: Callback function to notify UI status.

        Returns:
            True if successfully copied, False otherwise.
        """
        if not text:
            if callback_notify:
                callback_notify("Nothing to copy.")
            return False

        try:
            if self.root:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                self.root.update()  # Required on some OS platforms to keep clipboard content active

            # Cancel any previously running clear timer
            if self._timer and self._timer.is_alive():
                self._timer.cancel()

            if callback_notify:
                callback_notify(f"Copied! Clipboard will auto-clear in {self.auto_clear_seconds}s.")

            # Schedule auto clear in background thread
            self._timer = threading.Timer(
                self.auto_clear_seconds,
                self._clear_clipboard,
                args=[text, callback_notify]
            )
            self._timer.daemon = True
            self._timer.start()
            return True

        except Exception:
            if callback_notify:
                callback_notify("Clipboard action failed.")
            return False

    def _clear_clipboard(self, expected_content: str, callback_notify: Optional[Callable[[str], None]] = None):
        """Background callback to clear clipboard if content hasn't been changed by user."""
        try:
            if self.root:
                # Only clear if current clipboard content matches what we copied
                try:
                    current = self.root.clipboard_get()
                    if current == expected_content:
                        self.root.clipboard_clear()
                        if callback_notify:
                            self.root.after(0, lambda: callback_notify("Clipboard auto-cleared for privacy."))
                except Exception:
                    # Clipboard may have been overwritten or modified by another application
                    pass
        except Exception:
            pass


def get_strength_color(label: str) -> str:
    """
    Returns hex color code for strength label matching modern dark theme.
    """
    colors = {
        "VERY WEAK": "#f85149",    # Bright Red
        "WEAK": "#ff7b72",         # Soft Red / Coral
        "FAIR": "#d29922",         # Amber / Yellow
        "GOOD": "#e3b341",         # Gold / Light Amber
        "STRONG": "#3fb950",       # Bright Emerald Green
        "VERY STRONG": "#2ea043"   # Deep Security Green
    }
    return colors.get(label, "#8b949e")


def get_badge_symbol(status: str) -> str:
    """Returns icon symbol for requirement badge status."""
    symbols = {
        "PASS": "✓",
        "WARNING": "⚠",
        "FAIL": "✕"
    }
    return symbols.get(status, "•")
