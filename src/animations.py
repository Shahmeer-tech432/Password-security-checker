"""
Password Security Analyzer - Animation Engine

Canvas-based animation utilities:
  - MatrixRain   : falling matrix glyph rain on a tk.Canvas
  - CircularGauge: 3D arc gauge with eased score animation
  - AnimatedBar  : segmented gradient strength bar with smooth fill

PRIVACY: No password data ever passes through this module.
All animations receive only score integers (0-100) and string labels.
"""

import tkinter as tk
import random
from typing import Optional, Callable


# ─── Score → gradient color ───────────────────────────────────────────────────
def score_color(score: int) -> str:
    """Map a 0–100 score to a gradient color (red → amber → green → teal)."""
    if score <= 15:  return "#f04050"
    if score <= 35:  return "#f07040"
    if score <= 55:  return "#e0a030"
    if score <= 70:  return "#a8c030"
    if score <= 88:  return "#3dba6e"
    return "#00e0a0"


# ─── Matrix Rain ──────────────────────────────────────────────────────────────
class MatrixRain:
    """
    Lightweight canvas matrix-rain animation.
    Renders falling glyphs (digits + katakana + symbols) on any tk.Canvas.
    After each frame, all rain items are lowered below any existing overlay items.

    Usage:
        rain = MatrixRain(canvas)
        rain.start()
        ...
        rain.stop()
    """

    GLYPHS = list(
        "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホ"
        "@#!?<>ABCDEFabcdef0123456789+-*/^&|~;:"
    )

    def __init__(self, canvas: tk.Canvas,
                 char_color: str = "#006840",
                 head_color: str = "#00ff88",
                 font_size: int = 11):
        self.canvas     = canvas
        self.char_color = char_color
        self.head_color = head_color
        self.font_size  = font_size
        self.font       = ('Consolas', font_size)
        self.col_w      = font_size + 4
        self.row_h      = font_size + 5
        self.columns: list  = []
        self.n_rows: int    = 0
        self._job: Optional[str] = None
        self._running   = False

    def start(self):
        """Begin animation after a short delay (allows canvas to size itself)."""
        self._running = True
        self.canvas.after(200, self._init)

    def stop(self):
        """Stop the animation and cancel any pending callbacks."""
        self._running = False
        if self._job:
            try:
                self.canvas.after_cancel(self._job)
            except Exception:
                pass
            self._job = None

    # ── Internal ──────────────────────────────────────────────────────────────
    def _init(self):
        if not self._running:
            return
        w = self.canvas.winfo_width() or 900
        h = self.canvas.winfo_height() or 55
        n_cols   = max(1, w // self.col_w)
        self.n_rows = max(1, h // self.row_h)

        self.columns = []
        for i in range(min(n_cols, 70)):          # cap at 70 columns for perf
            x      = i * self.col_w + self.col_w // 2
            y_head = random.randint(-self.n_rows * 4, 0) * self.row_h
            max_trail = min(self.n_rows, 14)
            trail  = random.randint(min(3, max_trail), max_trail)
            speed  = random.randint(1, 3)
            chars  = [random.choice(self.GLYPHS) for _ in range(trail + 2)]
            self.columns.append(
                {'x': x, 'y': y_head, 'trail': trail,
                 'speed': speed, 'tick': 0, 'chars': chars}
            )
        self._tick()

    def _fade(self, hex_color: str, alpha: float) -> str:
        """Linearly fade hex_color toward black by alpha (0=black, 1=full)."""
        r = int(int(hex_color[1:3], 16) * alpha)
        g = int(int(hex_color[3:5], 16) * alpha)
        b = int(int(hex_color[5:7], 16) * alpha)
        return f"#{r:02x}{g:02x}{b:02x}"

    def _tick(self):
        if not self._running:
            return
        self.canvas.delete("rain")
        h_px = self.n_rows * self.row_h

        for col in self.columns:
            col['tick'] += 1
            if col['tick'] >= col['speed']:
                col['tick'] = 0
                col['y'] += self.row_h
                if random.random() < 0.12:          # mutate a random glyph
                    col['chars'][random.randint(0, len(col['chars']) - 1)] = \
                        random.choice(self.GLYPHS)
                if col['y'] - col['trail'] * self.row_h > h_px:  # reset column
                    col['y']     = random.randint(-self.n_rows * 4, -self.n_rows) * self.row_h
                    max_trail = min(self.n_rows, 14)
                    col['trail'] = random.randint(min(3, max_trail), max_trail)
                    col['speed'] = random.randint(1, 3)

            trail = col['trail']
            for i in range(trail):
                yp = col['y'] - i * self.row_h
                if 0 <= yp <= h_px:
                    if i == 0:
                        color = self.head_color
                    else:
                        alpha = max(0.04, (1.0 - i / trail) ** 1.8)
                        color = self._fade(self.char_color, alpha)
                    self.canvas.create_text(
                        col['x'], yp,
                        text=col['chars'][i % len(col['chars'])],
                        fill=color, font=self.font, tags="rain")

        # Keep all rain items BELOW any overlay items (title text, badges)
        self.canvas.tag_lower("rain")
        self._job = self.canvas.after(85, self._tick)


# ─── 3D Circular Score Gauge ─────────────────────────────────────────────────
class CircularGauge:
    """
    3D-styled animated circular arc gauge for displaying a 0–100 score.

    Visual layers (bottom to top):
      1. Outer shadow oval  (depth illusion)
      2. Dark track arc     (full 270° background)
      3. Inner circle       (dark surface)
      4. Inner bevel ring   (subtle highlight)
      5. Animated fill arc  (colored, score-driven)
      6. Glass highlight    (thin top arc for 3D sheen)
      7. Score text + label (centered)
    """

    def __init__(self, parent: tk.Widget, size: int = 200, bg: str = "#111720"):
        self.size    = size
        self.bg      = bg
        self._cur    = 0.0        # current animated score
        self._target = 0          # target score
        self._label  = "VERY WEAK"
        self._job: Optional[str] = None

        self.canvas = tk.Canvas(
            parent, width=size, height=size,
            bg=bg, highlightthickness=0, bd=0)
        self.canvas.pack(pady=6)

        self._build_static_layers()

        m = self._m
        s = size
        # Dynamic fill arc
        self._arc_id = self.canvas.create_arc(
            m, m, s - m, s - m,
            start=225, extent=0,
            style='arc', outline=score_color(0), width=15)

        # Glass highlight arc (stays fixed; very thin, white, at top)
        hm = m + 8
        self.canvas.create_arc(
            hm, hm, s - hm, s - hm,
            start=250, extent=40,
            style='arc', outline="#ffffff", width=2)

        # Score text
        cx, cy = size // 2, size // 2
        self._t_score = self.canvas.create_text(
            cx, cy - 16,
            text="0",
            font=('Consolas', 28, 'bold'),
            fill=score_color(0))
        self._t_label = self.canvas.create_text(
            cx, cy + 14,
            text="VERY WEAK",
            font=('Segoe UI', 8, 'bold'),
            fill=score_color(0))
        self._t_denom = self.canvas.create_text(
            cx, cy + 28,
            text="/ 100",
            font=('Segoe UI', 7),
            fill="#2a3a4a")

    def _build_static_layers(self):
        s  = self.size
        m  = 16          # outer margin → inner arc edge
        self._m = m
        cx = s // 2
        cy = s // 2

        # 1. Outer shadow/depth oval
        self.canvas.create_oval(m - 10, m - 10, s - m + 10, s - m + 10,
                                fill="#060a0e", outline="#060a0e")

        # 2. Full track arc (270°, dark)
        self.canvas.create_arc(m, m, s - m, s - m,
                               start=225, extent=270,
                               style='arc', outline="#182030", width=15)

        # 3. Inner circle (dark surface behind text)
        r_inner = (s - 2 * m) // 2 - 16
        self.canvas.create_oval(cx - r_inner, cy - r_inner,
                                cx + r_inner, cy + r_inner,
                                fill=self.bg, outline="#0e1a26", width=2)

        # 4. Inner bevel ring highlight
        r_bevel = r_inner - 5
        self.canvas.create_oval(cx - r_bevel, cy - r_bevel,
                                cx + r_bevel, cy + r_bevel,
                                fill=self.bg, outline="#1e2d40", width=1)

    def set_score(self, score: int, label: str):
        """Animate the gauge to the new score with ease-out interpolation."""
        self._target = max(0, min(100, score))
        self._label  = label
        if self._job:
            try:
                self.canvas.after_cancel(self._job)
            except Exception:
                pass
        self._animate()

    def _animate(self):
        diff = self._target - self._cur
        if abs(diff) < 0.35:
            self._cur = float(self._target)
        else:
            self._cur += diff * 0.13   # ease-out: 13% per frame at ~60fps

        cur_int   = int(self._cur)
        cur_color = score_color(cur_int)
        extent    = (self._cur / 100.0) * 270

        self.canvas.itemconfig(self._arc_id, extent=extent, outline=cur_color)
        self.canvas.itemconfig(self._t_score, text=str(cur_int), fill=cur_color)
        self.canvas.itemconfig(self._t_label, text=self._label, fill=cur_color)

        if abs(self._target - self._cur) > 0.3:
            self._job = self.canvas.after(16, self._animate)    # ~60 fps


# ─── Smooth Animated Strength Bar ────────────────────────────────────────────
class AnimatedBar:
    """
    Horizontal canvas bar with segmented gradient coloring and smooth
    ease-out fill animation triggered by set_score(score).
    """

    _STOPS = [
        (15,  "#f04050"),   # very weak – red
        (35,  "#f07040"),   # weak      – orange
        (55,  "#e0a030"),   # fair      – amber
        (70,  "#a8c030"),   # good      – yellow-green
        (88,  "#3dba6e"),   # strong    – green
        (100, "#00e0a0"),   # v.strong  – teal
    ]

    def __init__(self, parent: tk.Widget, height: int = 22, bg: str = "#111720"):
        self._cur    = 0.0
        self._target = 0
        self._job: Optional[str] = None

        self.canvas = tk.Canvas(
            parent, height=height,
            bg="#0d1520", highlightthickness=0, bd=0)
        self.canvas.pack(fill='x', pady=(2, 6))

    def set_score(self, score: int):
        """Animate the bar fill to the given score (0–100)."""
        self._target = max(0, min(100, score))
        if self._job:
            try:
                self.canvas.after_cancel(self._job)
            except Exception:
                pass
        self._animate()

    def _animate(self):
        diff = self._target - self._cur
        if abs(diff) < 0.35:
            self._cur = float(self._target)
        else:
            self._cur += diff * 0.13

        self._draw(self._cur)

        if abs(self._target - self._cur) > 0.3:
            self._job = self.canvas.after(16, self._animate)

    def _draw(self, score: float):
        self.canvas.delete("bar")
        W = self.canvas.winfo_width() or 500
        H = self.canvas.winfo_height() or 22

        fill_w = int((score / 100.0) * W)
        if fill_w <= 0:
            return

        x = 0
        prev_s = 0
        for stop_score, stop_color in self._STOPS:
            seg_end = min(score, stop_score)
            if seg_end <= prev_s:
                break
            seg_w = int(((seg_end - prev_s) / 100.0) * W)
            if seg_w > 0:
                self.canvas.create_rectangle(
                    x, 0, x + seg_w, H,
                    fill=stop_color, width=0, tags="bar")
            x     += seg_w
            prev_s = stop_score
            if seg_end < stop_score:
                break

        # Bright right-edge "highlight tick" for a 3D depth feel
        if fill_w >= 4:
            self.canvas.create_rectangle(
                fill_w - 3, 0, fill_w, H,
                fill="#ffffff", width=0, stipple="gray25", tags="bar")
