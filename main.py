"""
Password Security Analyzer
Main Desktop Application Entry Point

Project: Password Security Analyzer v1.0
Target OS: Windows / Cross-Platform
GUI Framework: Python Tkinter + ttk
Privacy Model: 100% Local In-Memory Processing (Zero-Storage)

To run the application:
    python main.py
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox

# Fix Windows DPI blurriness: declare per-monitor DPI awareness before Tk() is created
try:
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(2)   # Per-Monitor DPI Aware v1
except AttributeError:
    try:
        ctypes.windll.user32.SetProcessDPIAware()    # Fallback for older Windows
    except Exception:
        pass
except Exception:
    pass

# Ensure the root directory is in python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.ui import PasswordSecurityApp


def main():
    """Main application execution function."""
    root = tk.Tk()

    # Center window on screen
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    width = 1120
    height = 740
    x = max(0, (screen_width - width) // 2)
    y = max(0, (screen_height - height) // 2)
    root.geometry(f"{width}x{height}+{x}+{y}")

    try:
        app = PasswordSecurityApp(root)
        root.mainloop()
    except Exception as err:
        import traceback
        traceback.print_exc()
        # Show the real exception type and message (never includes user password data)
        messagebox.showerror(
            "Application Error",
            f"Application failed to start:\n\n{type(err).__name__}: {err}\n\n"
            "Privacy guarantee: No password data was saved or logged."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
