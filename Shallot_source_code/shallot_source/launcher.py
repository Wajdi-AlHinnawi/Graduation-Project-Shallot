"""User-friendly launcher used as the PyInstaller entry point.

This script is what runs when an end user double-clicks
``Shallot.exe``. It boots a Tkinter status window on the main
thread and runs the asyncio proxy on a background thread, wiring
log messages and status updates between the two so the user sees a
clean Windows application instead of a black console window.

The GUI lifecycle drives the process lifecycle:

  * The window opens, shows the setup instructions, and the proxy
    starts in the background.
  * The user keeps the window open while they browse.
  * Closing the window (X button or Quit) stops the proxy cleanly
    and exits the process.

If anything goes wrong before the GUI can come up — e.g. the bundle
is missing ``directory_config.json`` — we fall back to a console
error message and a "press Enter to exit" prompt so a user who
double-clicked the .exe is not left staring at a closed window with
no explanation.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import threading
import traceback
from pathlib import Path


def _ensure_modules_importable() -> None:
    """Make ``shared.*`` and ``client.*`` importable from this script."""
    here = Path(__file__).resolve().parent
    if str(here) not in sys.path:
        sys.path.insert(0, str(here))


def _missing_config_message(install_dir: Path) -> str:
    config_path = install_dir / "directory_config.json"
    return (
        "\n[ERROR] This build is missing directory_config.json.\n"
        "       Without it the local proxy has no directory server URL or\n"
        "       pinned signing key, so it cannot verify the relay list.\n"
        "\n"
        f"       Expected file: {config_path}\n"
        "\n"
        "       This is a packaging bug. Please report it to the project\n"
        "       team so a corrected build can be issued.\n"
    )


def _fatal_console_message(text: str) -> int:
    """Show an error in the console (or a Tk dialog if console is gone).

    Used for problems that occur before the GUI window is up. We try
    Tk's messagebox so a windowed-build user still sees the message
    even though there is no console window.
    """
    sys.stderr.write(text)
    sys.stderr.flush()
    try:
        # If we can stand up a tiny invisible Tk root, we can show a
        # proper messagebox. This is best-effort; if Tk isn't usable
        # for any reason we just rely on the console message above.
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Shallot", text.strip())
        root.destroy()
    except Exception:
        # Console-only fallback. If the user double-clicked the .exe
        # there may be no console, but we've done what we can.
        try:
            input("Press Enter to exit...")
        except EOFError:
            pass
    return 2


class _GuiLogHandler(logging.Handler):
    """Stdlib logging handler that pushes records into the GUI window."""

    def __init__(self, window):
        super().__init__()
        self._window = window

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._window.post_log(self.format(record))
        except Exception:
            # Never let a logging failure kill the proxy. If the GUI
            # is gone (e.g. window already closed) silently drop.
            pass


class _StreamToLogQueue:
    """File-like wrapper that turns writes into GUI log lines.

    The proxy_client uses ``log_info``/``log_error`` from
    ``shared.logging_utils``, which underneath just call ``print()``
    to stdout. By redirecting sys.stdout/sys.stderr through this we
    capture everything those helpers emit without modifying them.
    """

    def __init__(self, window, original):
        self._window = window
        self._original = original
        self._buffer = ""

    def write(self, data: str) -> int:
        # Still echo to the original stream so a developer running
        # ``python launcher.py`` sees output in their terminal too.
        try:
            self._original.write(data)
            self._original.flush()
        except Exception:
            pass
        # Buffer until we see a newline, then push complete lines
        # into the GUI. Avoids splitting one log message across
        # multiple GUI rows when print() flushes mid-line.
        self._buffer += data
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            line = line.rstrip("\r")
            if line:
                self._window.post_log(line)
        return len(data)

    def flush(self) -> None:
        try:
            self._original.flush()
        except Exception:
            pass


def _run_asyncio_in_thread(coro_factory, on_loop_ready, on_exit) -> threading.Thread:
    """Start an asyncio event loop on a background thread.

    Returns the thread object. The factory is called inside the
    thread so any per-loop state (server objects, tasks) is created
    on the right thread. ``on_loop_ready`` is called with the loop
    object so the main thread has a handle to schedule shutdown on.
    ``on_exit`` is called once the loop has fully stopped.
    """
    def _runner() -> None:
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            on_loop_ready(loop)
            loop.run_until_complete(coro_factory())
        except Exception:
            traceback.print_exc()
        finally:
            try:
                # Cancel anything still alive so we don't leak tasks.
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )
            except Exception:
                pass
            try:
                loop.close()
            except Exception:
                pass
            on_exit()

    t = threading.Thread(target=_runner, name="proxy-asyncio", daemon=True)
    t.start()
    return t


def main() -> int:
    _ensure_modules_importable()

    from shared.runtime_paths import runtime_root
    from shared.security import DIRECTORY_CONFIG_PATH, get_or_create_control_token

    install_dir = runtime_root()

    # Fail fast if the build is missing its baked-in directory config.
    # This case is a packaging bug, not a runtime issue, so we surface
    # it with a dedicated error before doing anything else.
    if not DIRECTORY_CONFIG_PATH.exists():
        return _fatal_console_message(_missing_config_message(install_dir))

    # Generate the control-API bearer token (and the matching
    # extension/control_token.js) BEFORE the proxy or the GUI starts.
    # The extension reads control_token.js synchronously when its
    # popup loads, so the file must exist before the user clicks the
    # extension icon for the first time.
    try:
        get_or_create_control_token()
    except Exception as exc:
        return _fatal_console_message(
            f"\n[ERROR] Could not create control API token: {exc}\n"
        )

    # Stand up the GUI window. It is built but not shown yet — that
    # happens when we call .run() at the bottom of this function.
    from gui_window import StatusWindow

    # Holder for the asyncio loop. Populated from the background
    # thread once the loop is created so the main thread can call
    # loop.call_soon_threadsafe() for shutdown.
    state: dict = {"loop": None, "exited": False}

    def _on_loop_ready(loop: asyncio.AbstractEventLoop) -> None:
        state["loop"] = loop

    def _on_loop_exit() -> None:
        state["exited"] = True

    # The Quit handler called from the GUI thread. Schedules a
    # shutdown on the asyncio loop without blocking the GUI.
    def _on_quit() -> None:
        loop = state["loop"]
        if loop is None or loop.is_closed():
            return
        loop.call_soon_threadsafe(_request_shutdown, loop)

    window = StatusWindow(install_dir=install_dir, on_quit=_on_quit)

    # Reroute stdout/stderr through the GUI log queue so existing
    # ``print()``-based logging in proxy_client lands in the window.
    sys.stdout = _StreamToLogQueue(window, sys.__stdout__ or sys.stdout)
    sys.stderr = _StreamToLogQueue(window, sys.__stderr__ or sys.stderr)

    # Also attach a handler to the root logger so anything that uses
    # the stdlib ``logging`` module (PyInstaller adds a few of these)
    # ends up in the same place.
    root_logger = logging.getLogger()
    root_logger.addHandler(_GuiLogHandler(window))

    # Wire the proxy and directory status into the GUI status panel.
    # The proxy_client uses the existing log lines we already emit;
    # we look for those substrings and turn them into status updates.
    # This avoids modifying the proxy_client itself.
    original_post_log = window.post_log

    def _intercepted_post_log(line: str) -> None:
        # Surface a couple of well-known events as status changes.
        if "Local onion proxy listening" in line:
            window.post_status("proxy", "ok", "Running on 127.0.0.1:8080")
        elif "Directory cache is now served from the live directory server" in line:
            window.post_status("directory", "ok", "Connected — directory verified")
        elif "Directory cache could not be refreshed" in line or "directory server is unreachable" in line:
            window.post_status("directory", "bad", "Unreachable — see logs")
        elif "Local control API ready" in line:
            window.post_status("proxy", "ok", "Running with control API")
        original_post_log(line)

    window.post_log = _intercepted_post_log  # type: ignore[method-assign]

    # Initial status while we wait for the proxy to start.
    window.post_status("proxy", "warn", "Starting…")
    window.post_status("directory", "warn", "Connecting…")

    # Kick off the asyncio proxy on a background thread.
    async def _proxy_factory():
        from client.proxy_client import main as proxy_main
        await proxy_main()

    def _request_shutdown(loop: asyncio.AbstractEventLoop) -> None:
        """Cancel the running proxy task on the asyncio thread."""
        for task in asyncio.all_tasks(loop):
            task.cancel()

    _run_asyncio_in_thread(_proxy_factory, _on_loop_ready, _on_loop_exit)

    # Run the GUI on the main thread. Blocks until the window closes.
    try:
        window.run()
    except KeyboardInterrupt:
        pass

    # Window is closed. Make sure the asyncio loop has actually
    # stopped — _on_quit scheduled cancellation, but we wait briefly
    # for the thread to wind down so SocketServer shutdown messages
    # don't appear after our process is technically exiting.
    loop = state["loop"]
    if loop is not None and not loop.is_closed():
        loop.call_soon_threadsafe(_request_shutdown, loop)
    deadline = 0
    while not state["exited"] and deadline < 30:
        threading.Event().wait(0.1)
        deadline += 1

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Last-resort safety net. We must never let an uncaught
        # exception leave the user with a silently-closed window
        # (the case in a windowed PyInstaller build).
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "Shallot",
                "Unexpected error during launch:\n\n" + traceback.format_exc(),
            )
            root.destroy()
        except Exception:
            traceback.print_exc()
        sys.exit(1)
