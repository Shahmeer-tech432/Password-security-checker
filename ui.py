"""
Password Security Analyzer - Graphical User Interface (Tkinter / ttk)

Dark Cybersecurity Dashboard with 3D Animations and Extended Features:
  - Matrix rain header strip
  - 3D animated circular score gauge
  - Smooth segmented animated strength bar
  - Time-to-Crack estimator table
  - Password Comparison tab (Tab 4)
  - Export Analysis Report (text file, zero password data)
  - Existing: Generator, Educational Hashing, Clipboard Manager

PRIVACY GUARANTEE:
All controls use strictly local in-memory variables.
Passwords are NEVER logged, stored, printed, or transmitted.
The export report contains NO password data — only scores and metadata.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Optional
import datetime
import os

from src.analyzer import PasswordAnalyzer, AnalysisResult
from src.generator import PasswordGenerator
from src.security import SecurityEducationalModule
from src.utils import ClipboardManager, get_strength_color, get_badge_symbol
from src.animations import MatrixRain, CircularGauge, AnimatedBar, score_color


# ─── Color Palette ────────────────────────────────────────────────────────────
class C:
    """Refined cybersecurity dark-mode color palette."""
    BG_APP       = "#0a0e14"
    BG_CARD      = "#111720"
    BG_CARD2     = "#161d28"
    BG_INPUT     = "#1c2333"
    BG_HEADER    = "#0d1321"

    BORDER       = "#1e2d3d"
    BORDER_FOCUS = "#2d5986"
    DIVIDER      = "#1a2332"

    TEXT_PRIMARY = "#e8edf5"
    TEXT_SUB     = "#7a8899"
    TEXT_DIM     = "#4a5568"

    ACCENT       = "#4f9cf9"
    ACCENT_BRIGHT= "#6cb4ff"
    ACCENT_HOVER = "#2b6cce"
    ACCENT_GLOW  = "#1a3a6e"

    GREEN        = "#3dba6e"
    GREEN_DIM    = "#1e4d32"
    AMBER        = "#e0a030"
    AMBER_DIM    = "#4a3510"
    RED          = "#f05060"
    RED_DIM      = "#4a1520"


# ─── Strength score → color (mirrors animations.score_color) ─────────────────
def _sc(score: int) -> str:
    if score <= 15:  return "#f04050"
    if score <= 35:  return "#f07040"
    if score <= 55:  return "#e0a030"
    if score <= 70:  return "#a8c030"
    if score <= 88:  return "#3dba6e"
    return "#00e0a0"


# ─── Main Application ─────────────────────────────────────────────────────────
class PasswordSecurityApp:
    """Main Tkinter application with 3D animations and extended feature set."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Password Security Analyzer  —  v1.0")
        self.root.geometry("1160x800")
        self.root.minsize(1060, 720)
        self.root.configure(bg=C.BG_APP)

        # Logic engines
        self.analyzer      = PasswordAnalyzer()
        self.generator     = PasswordGenerator()
        self.clipboard_mgr = ClipboardManager(tk_root=self.root, auto_clear_seconds=30)

        # Current analysis result (kept for export)
        self._last_result: Optional[AnalysisResult] = None

        # UI state
        self.show_password_var  = tk.BooleanVar(value=False)
        self.gen_length_var     = tk.IntVar(value=16)
        self.gen_upper_var      = tk.BooleanVar(value=True)
        self.gen_lower_var      = tk.BooleanVar(value=True)
        self.gen_digits_var     = tk.BooleanVar(value=True)
        self.gen_symbols_var    = tk.BooleanVar(value=True)

        # Comparison tab state
        self.cmp_show_a_var = tk.BooleanVar(value=False)
        self.cmp_show_b_var = tk.BooleanVar(value=False)

        self._configure_styles()
        self._build_layout()

        self.password_entry.focus_set()
        self._on_password_changed()

    # =========================================================================
    # STYLES
    # =========================================================================
    def _configure_styles(self):
        s = ttk.Style()
        s.theme_use('default')

        s.configure('TFrame',     background=C.BG_APP)
        s.configure('Card.TFrame',background=C.BG_CARD)

        s.configure('TNotebook',  background=C.BG_APP, borderwidth=0,
                    tabmargins=[0, 0, 0, 0])
        s.configure('TNotebook.Tab',
                    background=C.BG_CARD, foreground=C.TEXT_SUB,
                    padding=[18, 10], font=('Segoe UI', 10, 'bold'),
                    borderwidth=0, focuscolor=C.BG_APP)
        s.map('TNotebook.Tab',
              background=[('selected', C.BG_CARD2), ('active', C.BG_INPUT)],
              foreground=[('selected', C.ACCENT_BRIGHT), ('active', C.TEXT_PRIMARY)])

        s.configure('TLabel',
                    background=C.BG_APP, foreground=C.TEXT_PRIMARY, font=('Segoe UI', 10))
        s.configure('Card.TLabel',
                    background=C.BG_CARD, foreground=C.TEXT_PRIMARY, font=('Segoe UI', 10))
        s.configure('Muted.TLabel',
                    background=C.BG_CARD, foreground=C.TEXT_SUB, font=('Segoe UI', 9))
        s.configure('SubHeader.TLabel',
                    background=C.BG_CARD, foreground=C.TEXT_PRIMARY, font=('Segoe UI', 10, 'bold'))

        s.configure('TButton',
                    background=C.BG_INPUT, foreground=C.TEXT_PRIMARY,
                    bordercolor=C.BORDER, font=('Segoe UI', 9, 'bold'),
                    padding=[12, 7], relief='flat')
        s.map('TButton',
              background=[('active', C.BORDER_FOCUS)],
              foreground=[('active', C.ACCENT_BRIGHT)])

        s.configure('Primary.TButton',
                    background=C.ACCENT, foreground='#ffffff',
                    font=('Segoe UI', 10, 'bold'), padding=[18, 9], relief='flat')
        s.map('Primary.TButton',
              background=[('active', C.ACCENT_HOVER), ('pressed', C.ACCENT_HOVER)])

        s.configure('TCheckbutton',
                    background=C.BG_CARD, foreground=C.TEXT_PRIMARY,
                    font=('Segoe UI', 10), focuscolor=C.BG_CARD)
        s.map('TCheckbutton',
              background=[('active', C.BG_CARD)],
              foreground=[('active', C.ACCENT_BRIGHT)])

        s.configure('Horizontal.TScale',
                    background=C.BG_CARD, troughcolor=C.BG_INPUT, sliderthickness=18)

    # =========================================================================
    # TOP-LEVEL LAYOUT
    # =========================================================================
    def _build_layout(self):
        self._build_header()
        self._build_rain_strip()
        tk.Frame(self.root, bg=C.ACCENT, height=2).pack(fill='x')   # accent rule

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=14, pady=8)

        self.tab_analyzer  = ttk.Frame(self.notebook)
        self.tab_generator = ttk.Frame(self.notebook)
        self.tab_education = ttk.Frame(self.notebook)
        self.tab_compare   = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_analyzer,  text="   \U0001f510  Analyzer   ")
        self.notebook.add(self.tab_generator, text="   \u26a1  Generator   ")
        self.notebook.add(self.tab_education, text="   \U0001f4d6  Concepts   ")
        self.notebook.add(self.tab_compare,   text="   \u2194  Compare   ")

        self._build_tab_analyzer()
        self._build_tab_generator()
        self._build_tab_education()
        self._build_tab_compare()
        self._build_footer()

    # ── Header (regular tk widgets) ───────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self.root, bg=C.BG_HEADER, pady=14, padx=22)
        hdr.pack(fill='x', side='top')

        left = tk.Frame(hdr, bg=C.BG_HEADER)
        left.pack(side='left')

        tk.Label(left, text="\U0001f512  Password Security Analyzer",
                 font=('Segoe UI', 20, 'bold'),
                 bg=C.BG_HEADER, fg=C.TEXT_PRIMARY).pack(anchor='w')
        tk.Label(left, text="Real-time strength analysis — Zero Cloud  \u00b7  Zero Logs  \u00b7  Zero Telemetry",
                 font=('Segoe UI', 9),
                 bg=C.BG_HEADER, fg=C.TEXT_SUB).pack(anchor='w', pady=(3, 0))

        right = tk.Frame(hdr, bg=C.BG_HEADER)
        right.pack(side='right')

        self._pill(right, "\U0001f512 Local Only",   C.ACCENT,   C.ACCENT_GLOW).pack(side='right', padx=(6, 0))
        self._pill(right, "\U0001f6e1 Zero Storage", C.GREEN,    C.GREEN_DIM  ).pack(side='right', padx=(6, 0))
        self._pill(right, "\U0001f510 No Telemetry", C.TEXT_SUB, C.BG_CARD    ).pack(side='right')

    def _pill(self, parent, text: str, fg: str, bg: str) -> tk.Label:
        return tk.Label(parent, text=text,
                        font=('Segoe UI', 9, 'bold'),
                        bg=bg, fg=fg,
                        padx=12, pady=5, relief='solid', bd=1)

    # ── Matrix Rain decorative strip ──────────────────────────────────────────
    def _build_rain_strip(self):
        """50-px canvas strip with matrix rain animation between header and tabs."""
        self.rain_canvas = tk.Canvas(
            self.root, height=50,
            bg="#070c12", highlightthickness=0, bd=0)
        self.rain_canvas.pack(fill='x')

        self.matrix_rain = MatrixRain(
            self.rain_canvas,
            char_color="#005030",
            head_color="#00ee80",
            font_size=10)
        self.matrix_rain.start()

    # =========================================================================
    # TAB 1 — PASSWORD ANALYZER
    # =========================================================================
    def _build_tab_analyzer(self):
        main = tk.Frame(self.tab_analyzer, bg=C.BG_APP)
        main.pack(fill='both', expand=True, pady=6)

        left  = tk.Frame(main, bg=C.BG_APP)
        left.pack(side='left', fill='both', expand=True, padx=(0, 6))

        right = tk.Frame(main, bg=C.BG_APP)
        right.pack(side='right', fill='both', expand=True, padx=(6, 0))

        # ── Input card ──────────────────────────────────────────────────────
        in_body = self._card(left, "\U0001f4dd  Password Input")
        ttk.Label(in_body, text="Type or paste a password to analyze in real-time:",
                  style='Muted.TLabel').pack(anchor='w', pady=(0, 8))

        entry_row = tk.Frame(in_body, bg=C.BG_CARD)
        entry_row.pack(fill='x')

        entry_wrap = tk.Frame(entry_row, bg=C.BORDER_FOCUS, bd=0)
        entry_wrap.pack(side='left', fill='x', expand=True, ipady=1, ipadx=1)

        self.password_entry = tk.Entry(
            entry_wrap, show="\u2022",
            font=('Consolas', 13),
            bg=C.BG_INPUT, fg=C.TEXT_PRIMARY,
            insertbackground=C.ACCENT_BRIGHT,
            relief='flat', bd=7)
        self.password_entry.pack(fill='x', expand=True)
        self.password_entry.bind('<KeyRelease>', lambda e: self._on_password_changed())

        self.btn_eye = tk.Button(
            entry_row, text="\U0001f441 Show",
            command=self._toggle_password_visibility,
            font=('Segoe UI', 9, 'bold'),
            bg=C.BG_INPUT, fg=C.TEXT_PRIMARY,
            activebackground=C.BORDER_FOCUS, activeforeground=C.ACCENT_BRIGHT,
            relief='flat', bd=0, padx=12, cursor='hand2')
        self.btn_eye.pack(side='left', padx=(6, 0), ipady=5)

        tk.Button(entry_row, text="\u2715 Clear",
                  command=self._clear_password_input,
                  font=('Segoe UI', 9),
                  bg=C.BG_INPUT, fg=C.TEXT_SUB,
                  activebackground=C.RED_DIM, activeforeground=C.RED,
                  relief='flat', bd=0, padx=10, cursor='hand2'
                  ).pack(side='left', padx=(4, 0), ipady=5)

        ttk.Label(in_body,
                  text="\U0001f512  Password processed live in memory — never saved or transmitted.",
                  style='Muted.TLabel').pack(anchor='w', pady=(10, 0))

        # ── Checklist card ───────────────────────────────────────────────────
        chk_body = self._card(left, "\u2713  Security Requirements Checklist")
        self.checklist_frame = tk.Frame(chk_body, bg=C.BG_CARD)
        self.checklist_frame.pack(fill='both', expand=True, pady=4)

        # ── RIGHT: Strength card with 3D gauge ───────────────────────────────
        str_body = self._card(right, "\U0001f4ca  Password Strength")

        gauge_row = tk.Frame(str_body, bg=C.BG_CARD)
        gauge_row.pack(fill='x', pady=(0, 4))

        # 3D Circular gauge (left in the row)
        self.gauge = CircularGauge(gauge_row, size=190, bg=C.BG_CARD)

        # Right of gauge: score label + bar info
        gauge_info = tk.Frame(gauge_row, bg=C.BG_CARD)
        gauge_info.pack(side='left', fill='both', expand=True, padx=(10, 0))

        lbl_row = tk.Frame(gauge_info, bg=C.BG_CARD)
        lbl_row.pack(fill='x', pady=(20, 4))

        self.lbl_strength_label = tk.Label(
            lbl_row, text="VERY WEAK",
            font=('Segoe UI', 17, 'bold'),
            bg=C.BG_CARD, fg=C.RED)
        self.lbl_strength_label.pack(side='left')

        self.lbl_score_num = tk.Label(
            lbl_row, text="0 / 100",
            font=('Consolas', 12, 'bold'),
            bg=C.BG_CARD, fg=C.TEXT_SUB)
        self.lbl_score_num.pack(side='right')

        # Animated segmented bar
        self.anim_bar = AnimatedBar(gauge_info, height=20, bg=C.BG_CARD)

        # Entropy + char breakdown
        info_row = tk.Frame(gauge_info, bg=C.BG_CARD)
        info_row.pack(fill='x', pady=(4, 0))

        self.lbl_entropy = ttk.Label(info_row, text="Entropy: 0.0 bits", style='Muted.TLabel')
        self.lbl_entropy.pack(side='left')

        self.lbl_char_breakdown = ttk.Label(
            info_row,
            text="Len: 0  L:0  U:0  D:0  S:0",
            style='Muted.TLabel')
        self.lbl_char_breakdown.pack(side='right')

        tk.Frame(gauge_info, bg=C.DIVIDER, height=1).pack(fill='x', pady=(10, 6))
        ttk.Label(gauge_info,
                  text="\u2139  Score uses entropy, diversity, length & pattern penalties.",
                  style='Muted.TLabel').pack(anchor='w')

        # ── Time to Crack card ───────────────────────────────────────────────
        crack_body = self._card(right, "\u23f1  Time to Crack Estimates")

        ttk.Label(crack_body,
                  text="Average guesses required (50% of keyspace). Based on entropy only — no password data.",
                  style='Muted.TLabel').pack(anchor='w', pady=(0, 8))

        self.crack_frame = tk.Frame(crack_body, bg=C.BG_CARD)
        self.crack_frame.pack(fill='x')

        # ── Recommendations card ─────────────────────────────────────────────
        rec_body = self._card(right, "\U0001f4a1  Recommendations & Warnings")

        self.recs_text = tk.Text(
            rec_body, height=7,
            bg=C.BG_INPUT, fg=C.TEXT_PRIMARY,
            font=('Segoe UI', 9),
            bd=0, padx=12, pady=10,
            wrap='word', relief='flat',
            selectbackground=C.BORDER_FOCUS)
        self.recs_text.pack(fill='both', expand=True)
        self.recs_text.config(state='disabled')

        # Export button below recommendations
        tk.Button(rec_body,
                  text="\U0001f4be  Export Analysis Report",
                  command=self._export_report,
                  font=('Segoe UI', 9, 'bold'),
                  bg=C.BG_INPUT, fg=C.ACCENT_BRIGHT,
                  activebackground=C.ACCENT_GLOW, activeforeground=C.ACCENT_BRIGHT,
                  relief='flat', bd=0, padx=14, pady=6, cursor='hand2'
                  ).pack(anchor='e', pady=(8, 0))

    # =========================================================================
    # TAB 2 — PASSWORD GENERATOR
    # =========================================================================
    def _build_tab_generator(self):
        main = tk.Frame(self.tab_generator, bg=C.BG_APP)
        main.pack(fill='both', expand=True, pady=6)

        body = self._card(main, "\u26a1  Cryptographically Secure Password Generator")

        ttk.Label(body,
                  text="Uses Python's secrets module (OS CSPRNG) — cryptographic quality randomness, never predictable.",
                  style='Muted.TLabel').pack(anchor='w', pady=(0, 16))

        ctrl = tk.Frame(body, bg=C.BG_CARD)
        ctrl.pack(fill='x')

        # Length slider
        len_row = tk.Frame(ctrl, bg=C.BG_CARD)
        len_row.pack(fill='x', pady=8)

        ttk.Label(len_row, text="Password Length:", style='SubHeader.TLabel').pack(side='left')

        self.lbl_len_val = tk.Label(
            len_row, text="16",
            font=('Consolas', 13, 'bold'),
            bg=C.ACCENT_GLOW, fg=C.ACCENT_BRIGHT,
            width=4, padx=6, pady=2)
        self.lbl_len_val.pack(side='right')

        self.scale_length = ttk.Scale(
            len_row, from_=8, to=64,
            variable=self.gen_length_var,
            orient='horizontal',
            command=self._on_gen_length_change)
        self.scale_length.pack(side='right', fill='x', expand=True, padx=16)

        tk.Frame(ctrl, bg=C.DIVIDER, height=1).pack(fill='x', pady=10)

        # Checkboxes
        chk_grid = tk.Frame(ctrl, bg=C.BG_CARD)
        chk_grid.pack(fill='x', pady=4)

        for (lbl, var, r, c) in [
            ("Uppercase  (A–Z)",   self.gen_upper_var,   0, 0),
            ("Lowercase  (a–z)",   self.gen_lower_var,   0, 1),
            ("Numbers  (0–9)",     self.gen_digits_var,  1, 0),
            ("Symbols  (!@#$%^&)", self.gen_symbols_var, 1, 1),
        ]:
            ttk.Checkbutton(chk_grid, text=lbl, variable=var).grid(
                row=r, column=c, sticky='w', padx=14, pady=7)

        tk.Frame(body, bg=C.DIVIDER, height=1).pack(fill='x', pady=14)

        ttk.Button(body, text="\u26a1  Generate Secure Password",
                   style='Primary.TButton',
                   command=self._generate_password).pack(anchor='w', pady=(0, 14))

        # Result display
        res_wrap = tk.Frame(body, bg=C.BORDER_FOCUS, bd=0)
        res_wrap.pack(fill='x', ipady=1, ipadx=1)

        res_inner = tk.Frame(res_wrap, bg=C.BG_INPUT)
        res_inner.pack(fill='x')

        self.gen_result_entry = tk.Entry(
            res_inner,
            font=('Consolas', 14, 'bold'),
            bg=C.BG_INPUT, fg=C.ACCENT_BRIGHT,
            bd=0, relief='flat',
            insertbackground=C.TEXT_PRIMARY)
        self.gen_result_entry.pack(side='left', fill='x', expand=True, ipady=10, padx=12)

        tk.Button(res_inner, text="\U0001f4cb  Copy",
                  command=self._copy_generated_password,
                  font=('Segoe UI', 10, 'bold'),
                  bg=C.ACCENT, fg='#ffffff',
                  activebackground=C.ACCENT_HOVER, activeforeground='#ffffff',
                  relief='flat', bd=0, padx=18, cursor='hand2').pack(side='right', fill='y')

        bot = tk.Frame(body, bg=C.BG_CARD)
        bot.pack(fill='x', pady=(12, 0))

        self.lbl_gen_status = ttk.Label(
            bot, text="Press Generate to create a secure password.",
            style='Muted.TLabel')
        self.lbl_gen_status.pack(side='left')

        tk.Button(bot, text="Send to Analyzer \u2192",
                  command=self._send_generated_to_analyzer,
                  font=('Segoe UI', 9),
                  bg=C.BG_INPUT, fg=C.TEXT_PRIMARY,
                  activebackground=C.ACCENT_GLOW, activeforeground=C.ACCENT_BRIGHT,
                  relief='flat', bd=0, padx=12, pady=5, cursor='hand2').pack(side='right')

    # =========================================================================
    # TAB 3 — EDUCATIONAL HASHING & CONCEPTS
    # =========================================================================
    def _build_tab_education(self):
        main = tk.Frame(self.tab_education, bg=C.BG_APP)
        main.pack(fill='both', expand=True, pady=6)

        top = tk.Frame(main, bg=C.BG_APP)
        top.pack(fill='x', pady=(0, 6))

        b1 = self._card(top, "\U0001f510  Hashing vs Encryption", side='left')
        self._ro_text(b1, height=9, text=SecurityEducationalModule.HASHING_VS_ENCRYPTION_TEXT)

        b2 = self._card(top, "\U0001f6e1  Modern Password Hashing (Argon2 / bcrypt / scrypt)", side='left')
        self._ro_text(b2, height=9, text=SecurityEducationalModule.MODERN_PASSWORD_HASHING_TEXT)

        demo_body = self._card(main, "\U0001f9ea  Interactive SHA-256 Hash Demo")

        ttk.Label(demo_body,
                  text="\u26a0  Educational demo only — uses text you type here, NEVER your analyzed passwords.",
                  style='Muted.TLabel').pack(anchor='w', pady=(0, 10))

        inp_row = tk.Frame(demo_body, bg=C.BG_CARD)
        inp_row.pack(fill='x', pady=(0, 4))

        ttk.Label(inp_row, text="Sample Text:", style='SubHeader.TLabel').pack(side='left', padx=(0, 12))

        wrap = tk.Frame(inp_row, bg=C.BORDER_FOCUS, bd=0)
        wrap.pack(side='left', fill='x', expand=True, ipady=1, ipadx=1)

        self.hash_demo_entry = tk.Entry(
            wrap, font=('Segoe UI', 10),
            bg=C.BG_INPUT, fg=C.TEXT_PRIMARY,
            insertbackground=C.ACCENT_BRIGHT,
            relief='flat', bd=5)
        self.hash_demo_entry.pack(fill='x', expand=True)
        self.hash_demo_entry.bind('<KeyRelease>', lambda e: self._on_hash_demo_changed())
        self.hash_demo_entry.insert(0, "Hello Cybersecurity World")

        digest_frame = tk.Frame(demo_body, bg=C.BG_INPUT, bd=0)
        digest_frame.pack(fill='x', pady=12)

        tk.Label(digest_frame, text="SHA-256 Hex Digest",
                 font=('Segoe UI', 9, 'bold'),
                 bg=C.BG_INPUT, fg=C.TEXT_SUB).pack(anchor='w', padx=12, pady=(8, 2))

        self.lbl_hash_output = tk.Label(
            digest_frame, text="",
            font=('Consolas', 11, 'bold'),
            bg=C.BG_INPUT, fg=C.ACCENT_BRIGHT,
            wraplength=960, justify='left', anchor='w')
        self.lbl_hash_output.pack(fill='x', padx=12, pady=(0, 10))

        self._on_hash_demo_changed()

    # =========================================================================
    # TAB 4 — PASSWORD COMPARISON  (NEW FEATURE)
    # =========================================================================
    def _build_tab_compare(self):
        """Side-by-side password strength comparison (in-memory only)."""
        main = tk.Frame(self.tab_compare, bg=C.BG_APP)
        main.pack(fill='both', expand=True, pady=6)

        # Banner
        banner = tk.Frame(main, bg=C.ACCENT_GLOW, pady=8, padx=16)
        banner.pack(fill='x', pady=(0, 8))

        tk.Label(banner,
                 text="\u2194  Password Comparison Tool — Evaluate two passwords side-by-side",
                 font=('Segoe UI', 11, 'bold'),
                 bg=C.ACCENT_GLOW, fg=C.ACCENT_BRIGHT).pack(side='left')
        tk.Label(banner,
                 text="\U0001f512 Neither password is stored",
                 font=('Segoe UI', 9),
                 bg=C.ACCENT_GLOW, fg=C.TEXT_SUB).pack(side='right')

        # Two columns
        cols = tk.Frame(main, bg=C.BG_APP)
        cols.pack(fill='both', expand=True)

        # --- Column A ---
        col_a = tk.Frame(cols, bg=C.BG_APP)
        col_a.pack(side='left', fill='both', expand=True, padx=(0, 6))

        body_a = self._card(col_a, "\U0001f535  Password A")

        # Entry A
        ea_wrap = tk.Frame(body_a, bg=C.BORDER_FOCUS, bd=0)
        ea_wrap.pack(fill='x', ipady=1, ipadx=1)

        self.cmp_entry_a = tk.Entry(
            ea_wrap, show="\u2022",
            font=('Consolas', 12),
            bg=C.BG_INPUT, fg=C.TEXT_PRIMARY,
            insertbackground=C.ACCENT_BRIGHT,
            relief='flat', bd=6)
        self.cmp_entry_a.pack(side='left', fill='x', expand=True)
        self.cmp_entry_a.bind('<KeyRelease>', lambda e: self._on_compare_changed())

        self.btn_eye_a = tk.Button(
            ea_wrap, text="\U0001f441",
            command=self._toggle_cmp_a,
            font=('Segoe UI', 9), bg=C.BG_INPUT, fg=C.TEXT_PRIMARY,
            relief='flat', bd=0, padx=8, cursor='hand2')
        self.btn_eye_a.pack(side='right', fill='y')

        # Result display A
        self.cmp_gauge_a = CircularGauge(body_a, size=170, bg=C.BG_CARD)
        self.cmp_bar_a   = AnimatedBar(body_a, height=16, bg=C.BG_CARD)

        self.cmp_lbl_a = tk.Label(
            body_a, text="Enter Password A",
            font=('Segoe UI', 10, 'bold'),
            bg=C.BG_CARD, fg=C.TEXT_SUB)
        self.cmp_lbl_a.pack(pady=(4, 0))

        self.cmp_detail_a = tk.Text(
            body_a, height=6,
            bg=C.BG_INPUT, fg=C.TEXT_PRIMARY,
            font=('Segoe UI', 9),
            bd=0, padx=8, pady=6, wrap='word', relief='flat')
        self.cmp_detail_a.pack(fill='both', expand=True, pady=(8, 0))
        self.cmp_detail_a.config(state='disabled')

        # --- Column B ---
        col_b = tk.Frame(cols, bg=C.BG_APP)
        col_b.pack(side='right', fill='both', expand=True, padx=(6, 0))

        body_b = self._card(col_b, "\U0001f7e0  Password B")

        eb_wrap = tk.Frame(body_b, bg=C.BORDER_FOCUS, bd=0)
        eb_wrap.pack(fill='x', ipady=1, ipadx=1)

        self.cmp_entry_b = tk.Entry(
            eb_wrap, show="\u2022",
            font=('Consolas', 12),
            bg=C.BG_INPUT, fg=C.TEXT_PRIMARY,
            insertbackground=C.ACCENT_BRIGHT,
            relief='flat', bd=6)
        self.cmp_entry_b.pack(side='left', fill='x', expand=True)
        self.cmp_entry_b.bind('<KeyRelease>', lambda e: self._on_compare_changed())

        self.btn_eye_b = tk.Button(
            eb_wrap, text="\U0001f441",
            command=self._toggle_cmp_b,
            font=('Segoe UI', 9), bg=C.BG_INPUT, fg=C.TEXT_PRIMARY,
            relief='flat', bd=0, padx=8, cursor='hand2')
        self.btn_eye_b.pack(side='right', fill='y')

        self.cmp_gauge_b = CircularGauge(body_b, size=170, bg=C.BG_CARD)
        self.cmp_bar_b   = AnimatedBar(body_b, height=16, bg=C.BG_CARD)

        self.cmp_lbl_b = tk.Label(
            body_b, text="Enter Password B",
            font=('Segoe UI', 10, 'bold'),
            bg=C.BG_CARD, fg=C.TEXT_SUB)
        self.cmp_lbl_b.pack(pady=(4, 0))

        self.cmp_detail_b = tk.Text(
            body_b, height=6,
            bg=C.BG_INPUT, fg=C.TEXT_PRIMARY,
            font=('Segoe UI', 9),
            bd=0, padx=8, pady=6, wrap='word', relief='flat')
        self.cmp_detail_b.pack(fill='both', expand=True, pady=(8, 0))
        self.cmp_detail_b.config(state='disabled')

        # Verdict bar
        self.verdict_frame = tk.Frame(main, bg=C.BG_CARD2, pady=10, padx=16)
        self.verdict_frame.pack(fill='x', pady=(8, 0))

        self.lbl_verdict = tk.Label(
            self.verdict_frame,
            text="Enter both passwords to see a comparison verdict.",
            font=('Segoe UI', 10, 'bold'),
            bg=C.BG_CARD2, fg=C.TEXT_SUB)
        self.lbl_verdict.pack()

    # =========================================================================
    # FOOTER
    # =========================================================================
    def _build_footer(self):
        tk.Frame(self.root, bg=C.DIVIDER, height=1).pack(fill='x')

        footer = tk.Frame(self.root, bg=C.BG_HEADER, pady=7, padx=20)
        footer.pack(fill='x', side='bottom')

        tk.Label(footer,
                 text="\U0001f512  Zero-Storage Privacy Model — Passwords evaluated in local memory only. Never saved, logged, or transmitted.",
                 font=('Segoe UI', 9),
                 bg=C.BG_HEADER, fg=C.TEXT_SUB).pack(side='left')

        self.lbl_status_msg = tk.Label(
            footer, text="\u25cf  Ready",
            font=('Segoe UI', 9, 'bold'),
            bg=C.BG_HEADER, fg=C.ACCENT)
        self.lbl_status_msg.pack(side='right')

    # =========================================================================
    # CARD & WIDGET HELPERS
    # =========================================================================
    def _card(self, parent: tk.Widget, title: str, side=None) -> tk.Frame:
        """Create a professional dark card with left accent stripe."""
        outer = tk.Frame(parent, bg=C.BORDER, bd=0)
        if side:
            outer.pack(side=side, fill='both', expand=True, pady=4, padx=4)
        else:
            outer.pack(fill='both', expand=True, pady=4, padx=0)

        inner = tk.Frame(outer, bg=C.BG_CARD, bd=0)
        inner.pack(fill='both', expand=True, padx=1, pady=1)

        tk.Frame(inner, bg=C.ACCENT, width=3, bd=0).pack(side='left', fill='y')

        content = tk.Frame(inner, bg=C.BG_CARD)
        content.pack(side='left', fill='both', expand=True)

        title_bar = tk.Frame(content, bg=C.BG_CARD, pady=0)
        title_bar.pack(fill='x', padx=14, pady=(12, 0))

        tk.Label(title_bar, text=title,
                 font=('Segoe UI', 11, 'bold'),
                 bg=C.BG_CARD, fg=C.TEXT_PRIMARY).pack(side='left', anchor='w')

        tk.Frame(content, bg=C.DIVIDER, height=1).pack(fill='x', padx=14, pady=(6, 0))

        body = tk.Frame(content, bg=C.BG_CARD, padx=14, pady=10)
        body.pack(fill='both', expand=True)
        return body

    def _ro_text(self, parent: tk.Widget, height: int = 8, text: str = "") -> tk.Text:
        """Read-only styled Text widget."""
        t = tk.Text(parent, height=height,
                    bg=C.BG_INPUT, fg=C.TEXT_PRIMARY,
                    font=('Segoe UI', 9),
                    bd=0, relief='flat',
                    padx=10, pady=10, wrap='word',
                    selectbackground=C.BORDER_FOCUS)
        t.pack(fill='both', expand=True)
        if text:
            t.insert('1.0', text)
        t.config(state='disabled')
        return t

    # =========================================================================
    # EVENT HANDLERS — ANALYZER
    # =========================================================================
    def _on_password_changed(self):
        pwd = self.password_entry.get()
        result: AnalysisResult = self.analyzer.analyze(pwd)
        self._last_result = result
        self._update_analysis_display(result)

    def _update_analysis_display(self, res: AnalysisResult):
        color = _sc(res.score)

        # 1. Animated gauge + bar
        self.gauge.set_score(res.score, res.strength_label)
        self.anim_bar.set_score(res.score)

        # 2. Strength label + score text
        self.lbl_strength_label.config(text=res.strength_label, fg=color)
        self.lbl_score_num.config(text=f"{res.score} / 100")

        # 3. Entropy + char breakdown
        self.lbl_entropy.config(text=f"Entropy: {res.entropy_bits} bits")
        cc = res.char_counts
        self.lbl_char_breakdown.config(
            text=f"Len:{res.password_len}  L:{cc['lowercase']}  U:{cc['uppercase']}  D:{cc['digits']}  S:{cc['symbols']}")

        # 4. Checklist
        for w in self.checklist_frame.winfo_children():
            w.destroy()

        for item in res.checklist:
            status = item["status"]
            symbol = get_badge_symbol(status)
            if status == "PASS":
                fg, bg = C.GREEN, C.GREEN_DIM
            elif status == "WARNING":
                fg, bg = C.AMBER, C.AMBER_DIM
            else:
                fg, bg = C.RED, C.RED_DIM

            row = tk.Frame(self.checklist_frame, bg=C.BG_CARD)
            row.pack(fill='x', pady=2)

            tk.Label(row, text=f" {symbol} ",
                     font=('Segoe UI', 9, 'bold'),
                     bg=bg, fg=fg, padx=4, pady=1).pack(side='left', padx=(0, 8))
            tk.Label(row, text=item['name'],
                     font=('Segoe UI', 9, 'bold'),
                     bg=C.BG_CARD, fg=fg, width=21, anchor='w').pack(side='left')
            tk.Label(row, text=item['detail'],
                     font=('Segoe UI', 9),
                     bg=C.BG_CARD, fg=C.TEXT_SUB, anchor='w').pack(side='left', fill='x', expand=True)

        # 5. Time to Crack table
        for w in self.crack_frame.winfo_children():
            w.destroy()

        for entry in res.crack_time_info:
            row = tk.Frame(self.crack_frame, bg=C.BG_CARD)
            row.pack(fill='x', pady=2)

            tk.Label(row, text=entry.get("icon", ""),
                     font=('Segoe UI', 10),
                     bg=C.BG_CARD, fg=C.TEXT_SUB, width=2).pack(side='left')
            tk.Label(row, text=entry["scenario"],
                     font=('Segoe UI', 9),
                     bg=C.BG_CARD, fg=C.TEXT_SUB, width=28, anchor='w').pack(side='left')
            tk.Label(row, text=entry["speed"],
                     font=('Consolas', 8),
                     bg=C.BG_CARD, fg=C.TEXT_DIM, width=8, anchor='w').pack(side='left')

            # Color the time based on duration
            t = entry["time"]
            if t == "Instantly" or "sec" in t or "min" in t:
                tc = C.RED
            elif "hrs" in t or "days" in t:
                tc = C.AMBER
            elif "months" in t or "years" in t:
                if "K years" in t or "M years" in t or "B years" in t:
                    tc = C.GREEN
                else:
                    tc = C.AMBER
            else:
                tc = C.GREEN

            tk.Label(row, text=t,
                     font=('Consolas', 9, 'bold'),
                     bg=C.BG_CARD, fg=tc, anchor='w').pack(side='left', fill='x', expand=True)

        # 6. Recommendations
        self.recs_text.config(state='normal')
        self.recs_text.delete('1.0', tk.END)
        self.recs_text.tag_configure('warn_hdr', foreground=C.AMBER, font=('Segoe UI', 9, 'bold'))
        self.recs_text.tag_configure('rec_hdr',  foreground=C.ACCENT, font=('Segoe UI', 9, 'bold'))

        if res.warnings:
            self.recs_text.insert(tk.END, "\u26a0  WARNINGS\n", 'warn_hdr')
            for w in res.warnings:
                self.recs_text.insert(tk.END, f"  {w}\n")
            self.recs_text.insert(tk.END, "\n")

        if res.recommendations:
            self.recs_text.insert(tk.END, "\U0001f4a1  RECOMMENDATIONS\n", 'rec_hdr')
            for r in res.recommendations:
                self.recs_text.insert(tk.END, f"  \u2022  {r}\n")

        self.recs_text.config(state='disabled')

    def _toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="\u2022")
            self.btn_eye.config(text="\U0001f441 Show")
            self.show_password_var.set(False)
        else:
            self.password_entry.config(show="")
            self.btn_eye.config(text="\U0001f648 Hide")
            self.show_password_var.set(True)

    def _clear_password_input(self):
        self.password_entry.delete(0, tk.END)
        self._on_password_changed()
        self._set_status("\u25cf  Cleared")

    # =========================================================================
    # EVENT HANDLERS — GENERATOR
    # =========================================================================
    def _on_gen_length_change(self, val):
        try:
            self.lbl_len_val.config(text=str(int(float(val))))
        except Exception:
            pass

    def _generate_password(self):
        try:
            pwd = self.generator.generate(
                length=self.gen_length_var.get(),
                include_uppercase=self.gen_upper_var.get(),
                include_lowercase=self.gen_lower_var.get(),
                include_numbers=self.gen_digits_var.get(),
                include_symbols=self.gen_symbols_var.get())
            self.gen_result_entry.delete(0, tk.END)
            self.gen_result_entry.insert(0, pwd)
            self.lbl_gen_status.config(text="Generated using OS CSPRNG (secrets module).")
            self._set_status("\u25cf  Password generated")
        except ValueError as err:
            messagebox.showwarning("Generator Error", str(err))

    def _copy_generated_password(self):
        pwd = self.gen_result_entry.get()
        if not pwd:
            messagebox.showinfo("Clipboard", "Please generate a password first.")
            return

        def notify(msg: str):
            self.lbl_gen_status.config(text=msg)
            self._set_status(f"\u25cf  {msg}")

        self.clipboard_mgr.copy_to_clipboard(pwd, callback_notify=notify)

    def _send_generated_to_analyzer(self):
        pwd = self.gen_result_entry.get()
        if not pwd:
            messagebox.showinfo("Analyzer", "Please generate a password first.")
            return
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, pwd)
        self.notebook.select(self.tab_analyzer)
        self._on_password_changed()
        self._set_status("\u25cf  Loaded into Analyzer")

    # =========================================================================
    # EVENT HANDLERS — COMPARE
    # =========================================================================
    def _on_compare_changed(self):
        """Analyze both comparison passwords and update side-by-side displays."""
        pwd_a = self.cmp_entry_a.get()
        pwd_b = self.cmp_entry_b.get()

        res_a = self.analyzer.analyze(pwd_a)
        res_b = self.analyzer.analyze(pwd_b)

        self._update_compare_side(
            res_a, self.cmp_gauge_a, self.cmp_bar_a,
            self.cmp_lbl_a, self.cmp_detail_a, "A")
        self._update_compare_side(
            res_b, self.cmp_gauge_b, self.cmp_bar_b,
            self.cmp_lbl_b, self.cmp_detail_b, "B")

        self._update_verdict(res_a, res_b, pwd_a, pwd_b)

    def _update_compare_side(self, res: AnalysisResult,
                             gauge: CircularGauge, bar: AnimatedBar,
                             lbl: tk.Label, detail: tk.Text, side: str):
        if res.password_len == 0:
            gauge.set_score(0, "VERY WEAK")
            bar.set_score(0)
            lbl.config(text=f"Enter Password {side}", fg=C.TEXT_SUB)
            detail.config(state='normal')
            detail.delete('1.0', tk.END)
            detail.config(state='disabled')
            return

        color = _sc(res.score)
        gauge.set_score(res.score, res.strength_label)
        bar.set_score(res.score)
        lbl.config(text=res.strength_label, fg=color)

        detail.config(state='normal')
        detail.delete('1.0', tk.END)
        cc = res.char_counts
        detail.insert(tk.END,
                      f"Score: {res.score}/100  |  Entropy: {res.entropy_bits} bits\n"
                      f"Length: {res.password_len}  "
                      f"Lower:{cc['lowercase']}  Upper:{cc['uppercase']}  "
                      f"Digits:{cc['digits']}  Symbols:{cc['symbols']}\n\n")
        if res.warnings:
            for w in res.warnings:
                detail.insert(tk.END, f"\u26a0 {w}\n")
        if not res.recommendations:
            detail.insert(tk.END, "\u2713 No issues found.")
        else:
            for r in res.recommendations[:3]:
                detail.insert(tk.END, f"\u2022 {r}\n")
        detail.config(state='disabled')

    def _update_verdict(self, ra: AnalysisResult, rb: AnalysisResult,
                        pwd_a: str, pwd_b: str):
        if ra.password_len == 0 or rb.password_len == 0:
            self.lbl_verdict.config(
                text="Enter both passwords to see a comparison verdict.",
                fg=C.TEXT_SUB)
            return

        diff = rb.score - ra.score
        if diff == 0:
            msg  = "\u2194  Both passwords have equal strength scores."
            color = C.ACCENT
        elif diff > 0:
            pct  = abs(diff)
            msg  = f"\U0001f7e0  Password B is stronger by {pct} points  ({rb.score} vs {ra.score})"
            color = C.GREEN
        else:
            pct  = abs(diff)
            msg  = f"\U0001f535  Password A is stronger by {pct} points  ({ra.score} vs {rb.score})"
            color = C.GREEN

        self.lbl_verdict.config(text=msg, fg=color)

    def _toggle_cmp_a(self):
        if self.cmp_show_a_var.get():
            self.cmp_entry_a.config(show="\u2022")
            self.cmp_show_a_var.set(False)
        else:
            self.cmp_entry_a.config(show="")
            self.cmp_show_a_var.set(True)

    def _toggle_cmp_b(self):
        if self.cmp_show_b_var.get():
            self.cmp_entry_b.config(show="\u2022")
            self.cmp_show_b_var.set(False)
        else:
            self.cmp_entry_b.config(show="")
            self.cmp_show_b_var.set(True)

    # =========================================================================
    # EVENT HANDLERS — HASH DEMO
    # =========================================================================
    def _on_hash_demo_changed(self):
        sample = self.hash_demo_entry.get()
        res    = SecurityEducationalModule.generate_sha256_demo(sample)
        self.lbl_hash_output.config(
            text=res["hex_digest"] if res["hex_digest"] else "(Empty input)")

    # =========================================================================
    # EXPORT REPORT  (NEW FEATURE — zero password data)
    # =========================================================================
    def _export_report(self):
        """Save a plain-text analysis report. Never includes the actual password."""
        res = self._last_result
        if res is None or res.password_len == 0:
            messagebox.showinfo(
                "Export Report",
                "Please enter and analyze a password before exporting.")
            return

        # Build file path via save dialog
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"password_analysis_{timestamp}.txt"
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile=default_name,
            title="Save Analysis Report")

        if not path:
            return  # user cancelled

        # Build report text (NEVER includes the password itself)
        lines = [
            "=" * 64,
            "  PASSWORD SECURITY ANALYSIS REPORT",
            f"  Generated : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "  Application: Password Security Analyzer v1.0",
            "=" * 64,
            "",
            "  PRIVACY NOTICE:",
            "  This report contains NO password data.",
            "  All analysis was performed in local memory only.",
            "",
            "-" * 64,
            "  ANALYSIS RESULTS",
            "-" * 64,
            f"  Password Length : {res.password_len} characters",
            f"  Strength Label  : {res.strength_label}",
            f"  Security Score  : {res.score} / 100",
            f"  Shannon Entropy : {res.entropy_bits} bits",
            f"  Lowercase chars : {res.char_counts['lowercase']}",
            f"  Uppercase chars : {res.char_counts['uppercase']}",
            f"  Digit chars     : {res.char_counts['digits']}",
            f"  Symbol chars    : {res.char_counts['symbols']}",
            "",
            "-" * 64,
            "  SECURITY REQUIREMENTS CHECKLIST",
            "-" * 64,
        ]

        for item in res.checklist:
            status = f"[{item['status']:<7}]"
            lines.append(f"  {status}  {item['name']:<30} {item['detail']}")

        lines += ["", "-" * 64, "  TIME TO CRACK ESTIMATES", "-" * 64]
        for entry in res.crack_time_info:
            scenario = entry["scenario"]
            speed    = entry["speed"]
            t        = entry["time"]
            lines.append(f"  {scenario:<34} ({speed:<8})  {t}")

        if res.warnings:
            lines += ["", "-" * 64, "  WARNINGS", "-" * 64]
            for w in res.warnings:
                lines.append(f"  {w}")

        if res.recommendations:
            lines += ["", "-" * 64, "  RECOMMENDATIONS", "-" * 64]
            for r in res.recommendations:
                lines.append(f"  * {r}")

        lines += ["", "=" * 64]

        report_text = "\n".join(lines)

        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(report_text)
            messagebox.showinfo(
                "Report Exported",
                f"Analysis report saved to:\n{path}\n\nNO password data was included.")
            self._set_status(f"\u25cf  Report saved")
        except Exception as err:
            messagebox.showerror("Export Failed", f"Could not save report:\n{err}")

    # =========================================================================
    # SHARED UTILITIES
    # =========================================================================
    def _set_status(self, msg: str):
        self.lbl_status_msg.config(text=msg)
