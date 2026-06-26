"""Tkinter status window shown when Shallot.exe runs.

Replaces the bare console window the .exe used to open with a
proper Windows application window. The window contains:

  * A header with the app title.
  * Three numbered setup steps (proxy address, extension folder path,
    where to click in the browser).
  * A status panel with two lights:
      - Local proxy: green when listening on 127.0.0.1:8080.
      - Directory server: green when the latest signed directory was
        verified successfully, red while it is unreachable.
  * A "Show logs" toggle that, when expanded, reveals a scrolling
    text widget with the proxy's log output. Hidden by default so a
    non-technical user does not see noisy per-session log lines.
  * A "Quit" button that stops the proxy and closes the window.

Closing the window via the X button is treated identically to
clicking Quit: the proxy is stopped cleanly and the process exits.

Threading model
---------------
Tkinter must run on the main thread on Windows. The proxy_client's
asyncio event loop runs on a background thread and posts updates back
to the GUI through a thread-safe queue, drained on Tk's idle callback.
This keeps Tk responsive while the proxy is busy and avoids any
"calling Tk from another thread" crashes.
"""
from __future__ import annotations

import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import scrolledtext, ttk
from typing import Callable, Optional


# Color palette. We deliberately avoid the bright primary colors that
# come out of stock Tk (#0000FF blue, #00FF00 lime). The palette below
# matches modern Windows 11 accent styling without being garish.
COLOR_BG = "#1e1f22"            # window background
COLOR_PANEL = "#2b2d31"         # panels / cards
COLOR_TEXT = "#e3e5e8"          # main text
COLOR_TEXT_MUTED = "#a3a6aa"    # secondary text
COLOR_ACCENT = "#5865f2"        # primary accent (used for headings)
COLOR_OK = "#23a559"            # success / running indicator
COLOR_BAD = "#e64545"           # error / disconnected indicator
COLOR_WARN = "#e6a23c"          # warning / connecting indicator
COLOR_BUTTON = "#3a3c42"        # idle button bg
COLOR_BUTTON_HOVER = "#4a4c52"  # hover button bg


class StatusWindow:
    """The application's main window."""

    def __init__(self, install_dir: Path, on_quit: Callable[[], None]):
        """Build the window. Does not enter the event loop yet.

        Parameters
        ----------
        install_dir
            The directory that contains Shallot.exe. Shown in the
            instructions and in the "Open install folder" link.
        on_quit
            A callback the launcher provides; we invoke it when the
            user closes the window or clicks Quit, so the launcher
            can shut the proxy down before the process exits.
        """
        self._install_dir = install_dir
        self._on_quit = on_quit
        # Thread-safe queues used to feed status changes and log lines
        # in from the asyncio thread. The window drains these on every
        # idle tick.
        self._status_q: "queue.Queue[tuple[str, str]]" = queue.Queue()
        self._log_q: "queue.Queue[str]" = queue.Queue()
        # Track whether the log panel is expanded so we can resize the
        # window appropriately when the user toggles it.
        self._logs_visible = False

        self._build_window()

    # ------------------------------------------------------------------
    # Window construction
    # ------------------------------------------------------------------

    def _build_window(self) -> None:
        self.root = tk.Tk()
        self.root.title("Shallot — Privacy-Preserving Onion-Network")
        # 720x520 fits the instruction text comfortably on a 1080p screen
        # without feeling oversized. We expand to 720x720 only when the
        # user opens the log panel.
        self.root.geometry("720x520")
        self.root.minsize(720, 520)
        self.root.configure(bg=COLOR_BG)

        # Use the bundled icon if it ships next to the launcher.
        # bundle_resource_root() handles both frozen and dev runs.
        try:
            from shared.runtime_paths import bundle_resource_root
            icon_path = bundle_resource_root() / "Shallot.ico"
            if icon_path.exists():
                self.root.iconbitmap(default=str(icon_path))
        except Exception:
            # An icon is purely cosmetic; failing to load it should
            # never prevent the window from opening.
            pass

        # Window-X intercept: route through our quit handler so the
        # launcher's on_quit runs and the asyncio loop is shut down
        # cleanly. Without this, closing the window leaves orphaned
        # asyncio tasks in the background.
        self.root.protocol("WM_DELETE_WINDOW", self._handle_quit)

        # ttk styling. We keep this minimal — Tk's default theme is
        # actually fine on Windows 11; we just override colors.
        style = ttk.Style(self.root)
        style.theme_use("clam")  # 'clam' is the most consistent across platforms
        style.configure("TFrame", background=COLOR_BG)
        style.configure("Panel.TFrame", background=COLOR_PANEL)
        style.configure(
            "TLabel",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Heading.TLabel",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
            font=("Segoe UI", 16, "bold"),
        )
        style.configure(
            "Subheading.TLabel",
            background=COLOR_BG,
            foreground=COLOR_TEXT_MUTED,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Step.TLabel",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
            font=("Segoe UI", 10),
        )
        style.configure(
            "StepNum.TLabel",
            background=COLOR_BG,
            foreground=COLOR_ACCENT,
            font=("Segoe UI", 12, "bold"),
        )
        style.configure(
            "Status.TLabel",
            background=COLOR_PANEL,
            foreground=COLOR_TEXT,
            font=("Segoe UI", 10),
        )
        style.configure(
            "StatusLabel.TLabel",
            background=COLOR_PANEL,
            foreground=COLOR_TEXT_MUTED,
            font=("Segoe UI", 9),
        )

        # Outer padding container.
        outer = ttk.Frame(self.root, style="TFrame", padding=20)
        outer.pack(fill="both", expand=True)

        self._build_header(outer)
        self._build_steps(outer)
        self._build_status_panel(outer)
        self._build_logs_section(outer)
        self._build_footer(outer)

        # Start the queue-drain loop. Runs every 100 ms.
        self.root.after(100, self._drain_queues)

    def _build_header(self, parent: ttk.Frame) -> None:
        header = ttk.Frame(parent, style="TFrame")
        header.pack(fill="x", pady=(0, 12))
        ttk.Label(
            header,
            text="Shallot",
            style="Heading.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            header,
            text="Privacy-Preserving Onion-Network — local client",
            style="Subheading.TLabel",
        ).pack(anchor="w")

    def _build_steps(self, parent: ttk.Frame) -> None:
        """Three numbered setup steps shown to the user."""
        steps_frame = ttk.Frame(parent, style="TFrame")
        steps_frame.pack(fill="x", pady=(0, 14))

        ttk.Label(
            steps_frame,
            text="To start browsing privately:",
            style="TLabel",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        # Each step is a small inner frame so we can lay out the
        # number and the description as a two-column grid.
        steps = [
            (
                "1",
                "In Windows Settings → Network & Internet → Proxy, set the proxy "
                "to ON with address 127.0.0.1 and port 8080.",
            ),
            (
                "2",
                "In Chrome (or any Chromium browser), open chrome://extensions, "
                "enable Developer Mode, click Load unpacked, and select:\n"
                f"{self._install_dir / 'extension'}",
            ),
            (
                "3",
                "Click the Shallot extension icon in the browser toolbar to "
                "see the active relay circuit and toggle privacy options.",
            ),
        ]
        for num, text in steps:
            row = ttk.Frame(steps_frame, style="TFrame")
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=num, style="StepNum.TLabel", width=2).pack(
                side="left", anchor="n", padx=(0, 8)
            )
            ttk.Label(
                row, text=text, style="Step.TLabel", wraplength=620, justify="left"
            ).pack(side="left", anchor="w", fill="x", expand=True)

    def _build_status_panel(self, parent: ttk.Frame) -> None:
        """Status panel showing live proxy and directory-server health."""
        # Visual card using a Frame with its own background color.
        panel = tk.Frame(
            parent,
            bg=COLOR_PANEL,
            highlightthickness=0,
            bd=0,
        )
        panel.pack(fill="x", pady=(4, 10))

        inner = tk.Frame(panel, bg=COLOR_PANEL, padx=14, pady=10)
        inner.pack(fill="x")

        tk.Label(
            inner,
            text="Status",
            bg=COLOR_PANEL,
            fg=COLOR_TEXT,
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", pady=(0, 6))

        # Two status rows: proxy listener and directory connection.
        # Each row is a colored dot + label + state text.
        self._status_widgets: dict[str, dict] = {}
        for key, label in (
            ("proxy", "Local proxy"),
            ("directory", "Directory server"),
        ):
            row = tk.Frame(inner, bg=COLOR_PANEL)
            row.pack(fill="x", pady=2)
            dot = tk.Canvas(
                row, width=12, height=12, bg=COLOR_PANEL, highlightthickness=0
            )
            dot.create_oval(2, 2, 10, 10, fill=COLOR_WARN, outline="")
            dot.pack(side="left", padx=(0, 8))
            tk.Label(
                row,
                text=label,
                bg=COLOR_PANEL,
                fg=COLOR_TEXT_MUTED,
                font=("Segoe UI", 10),
                width=18,
                anchor="w",
            ).pack(side="left")
            value = tk.Label(
                row,
                text="Starting…",
                bg=COLOR_PANEL,
                fg=COLOR_TEXT,
                font=("Segoe UI", 10),
                anchor="w",
            )
            value.pack(side="left", fill="x", expand=True)
            self._status_widgets[key] = {"dot": dot, "value": value}

    def _build_logs_section(self, parent: ttk.Frame) -> None:
        """Collapsible log area, hidden by default."""
        # The toggle button row.
        toggle_row = ttk.Frame(parent, style="TFrame")
        toggle_row.pack(fill="x", pady=(0, 6))
        self._toggle_btn = tk.Button(
            toggle_row,
            text="▸ Show logs",
            command=self._toggle_logs,
            bg=COLOR_BUTTON,
            fg=COLOR_TEXT,
            activebackground=COLOR_BUTTON_HOVER,
            activeforeground=COLOR_TEXT,
            relief="flat",
            font=("Segoe UI", 9),
            cursor="hand2",
            bd=0,
            padx=12,
            pady=4,
        )
        self._toggle_btn.pack(side="left")

        # Log frame — built but not packed. Pack only when expanded.
        self._logs_frame = tk.Frame(parent, bg=COLOR_BG)
        self._logs_text = scrolledtext.ScrolledText(
            self._logs_frame,
            height=12,
            bg="#0f1014",
            fg="#c8c9cc",
            insertbackground=COLOR_TEXT,
            font=("Consolas", 9),
            relief="flat",
            bd=0,
            wrap="none",
            state="disabled",
        )
        self._logs_text.pack(fill="both", expand=True, padx=2, pady=2)

    def _build_footer(self, parent: ttk.Frame) -> None:
        # Spacer pushes the footer to the bottom when logs are hidden.
        spacer = ttk.Frame(parent, style="TFrame")
        spacer.pack(fill="both", expand=True)

        footer = ttk.Frame(parent, style="TFrame")
        footer.pack(fill="x", pady=(8, 0))

        ttk.Label(
            footer,
            text=f"Install folder: {self._install_dir}",
            style="Subheading.TLabel",
        ).pack(side="left")

        # Quit button on the right.
        self._quit_btn = tk.Button(
            footer,
            text="Quit",
            command=self._handle_quit,
            bg=COLOR_BUTTON,
            fg=COLOR_TEXT,
            activebackground=COLOR_BUTTON_HOVER,
            activeforeground=COLOR_TEXT,
            relief="flat",
            font=("Segoe UI", 10),
            cursor="hand2",
            bd=0,
            padx=18,
            pady=4,
        )
        self._quit_btn.pack(side="right")

    # ------------------------------------------------------------------
    # Public API used by the launcher / log handler
    # ------------------------------------------------------------------

    def post_status(self, key: str, state: str, text: str) -> None:
        """Thread-safe status update.

        ``state`` must be one of "ok", "bad", "warn".
        Called from the asyncio thread; the actual widget update
        happens on the Tk main thread via the queue drain.
        """
        self._status_q.put((key, f"{state}|{text}"))

    def post_log(self, message: str) -> None:
        """Thread-safe append to the log widget."""
        # Bound the queue size to avoid unbounded memory growth if
        # something causes a log storm and the GUI falls behind.
        if self._log_q.qsize() < 5000:
            self._log_q.put(message)

    def run(self) -> None:
        """Enter the Tk main loop. Blocks until the window closes."""
        self.root.mainloop()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _toggle_logs(self) -> None:
        """Show or hide the log panel."""
        if self._logs_visible:
            self._logs_frame.pack_forget()
            self._toggle_btn.config(text="▸ Show logs")
            self.root.geometry("720x520")
            self._logs_visible = False
        else:
            self._logs_frame.pack(fill="both", expand=True, pady=(0, 8))
            self._toggle_btn.config(text="▾ Hide logs")
            self.root.geometry("720x720")
            self._logs_visible = True

    def _drain_queues(self) -> None:
        """Pull pending status and log updates onto the GUI."""
        # Status updates: usually 0–2 per tick.
        while True:
            try:
                key, payload = self._status_q.get_nowait()
            except queue.Empty:
                break
            self._apply_status(key, payload)

        # Log lines: can be many per tick during startup. We append
        # them in one batch to avoid hammering the Text widget.
        new_lines = []
        while True:
            try:
                new_lines.append(self._log_q.get_nowait())
            except queue.Empty:
                break
        if new_lines:
            self._logs_text.config(state="normal")
            self._logs_text.insert("end", "\n".join(new_lines) + "\n")
            # Cap log buffer at ~2000 lines to keep it light.
            line_count = int(self._logs_text.index("end-1c").split(".")[0])
            if line_count > 2000:
                self._logs_text.delete("1.0", f"{line_count - 2000}.0")
            self._logs_text.see("end")
            self._logs_text.config(state="disabled")

        # Reschedule.
        self.root.after(100, self._drain_queues)

    def _apply_status(self, key: str, payload: str) -> None:
        """Update one of the status rows based on a queued message."""
        widgets = self._status_widgets.get(key)
        if not widgets:
            return
        state, text = payload.split("|", 1)
        color = {
            "ok": COLOR_OK,
            "bad": COLOR_BAD,
            "warn": COLOR_WARN,
        }.get(state, COLOR_WARN)
        widgets["dot"].delete("all")
        widgets["dot"].create_oval(2, 2, 10, 10, fill=color, outline="")
        widgets["value"].config(text=text)

    def _handle_quit(self) -> None:
        """Quit button or window-X close. Ask the launcher to clean up."""
        # Disable the button so the user can't double-click during shutdown.
        try:
            self._quit_btn.config(state="disabled", text="Stopping…")
        except tk.TclError:
            pass
        # Schedule the shutdown on the Tk thread so it completes after
        # the current event handler returns.
        self.root.after(50, self._do_quit)

    def _do_quit(self) -> None:
        try:
            self._on_quit()
        except Exception:
            # If the launcher's on_quit raises, we still want the
            # window to close cleanly.
            pass
        try:
            self.root.destroy()
        except tk.TclError:
            pass
