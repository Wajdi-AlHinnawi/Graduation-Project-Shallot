"""Resolve the directory the application uses for runtime state.

Why this exists
---------------
Various modules need to read or write small persistent files —
``directory_config.json`` (pinned directory-server URL and key),
``control_token_dev.txt`` (control-API bearer token), and
``extension/control_token.js`` (the same token written in a form the
unpacked browser extension can read). Historically these files were
located via ``Path(__file__).resolve().parent.parent``, which gives the
project root in a normal Python checkout.

That breaks under PyInstaller. When the proxy_client is bundled with
``--onedir``, ``__file__`` points into a hidden temporary unpack of the
bundle (or into ``_internal`` next to the .exe), not the directory where
the user installed our application. Files written there land in the
wrong place: the extension can't see ``control_token.js``, the user
cannot inspect ``directory_config.json``, and reruns of the .exe see no
prior state.

The fix is to resolve the runtime root in a frozen-aware way:

* When ``sys.frozen`` is True (running inside a PyInstaller bundle), use
  the directory containing the executable. Editable files like
  ``directory_config.json`` and the ``extension/`` folder live alongside
  ``Shallot.exe`` in our distribution.
* Otherwise, use the original two-levels-up-from-this-file path so
  ordinary ``python run/run_client.py`` invocations keep working without
  changes.

Modules should import :func:`runtime_root` rather than computing
``PROJECT_ROOT`` themselves.
"""
from __future__ import annotations

import sys
from pathlib import Path


def runtime_root() -> Path:
    """Return the directory where mutable runtime files live.

    For a PyInstaller-frozen build, this is the directory containing the
    executable. For a regular Python checkout, this is the project root.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    # In a normal checkout this file lives at <project>/shared/runtime_paths.py
    return Path(__file__).resolve().parent.parent


def bundle_resource_root() -> Path:
    """Return the directory where read-only bundled resources live.

    PyInstaller unpacks data files added with the ``datas=`` spec entry
    into a temporary directory whose path is exposed via
    ``sys._MEIPASS``. Use this for files that ship with the bundle and
    never need to be modified at runtime (e.g. icons).
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    return Path(__file__).resolve().parent.parent
