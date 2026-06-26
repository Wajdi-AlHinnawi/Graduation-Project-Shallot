from __future__ import annotations

import os
import threading
import time
from typing import Optional

_PRINT_LOCK = threading.Lock()
LOG_MODE = os.getenv("LOG_MODE", "demo").strip().lower() or "demo"
DEBUG_ENABLED = LOG_MODE == "debug"


def _render_prefix(component: str, session: Optional[str] = None, level: str = "info") -> str:
    parts = [f"[{time.strftime('%H:%M:%S')}]", f"[{component}]"]
    if session:
        parts.append(f"[session={session}]")
    if level == "error":
        parts.append("[ERROR]")
    return "".join(parts)


def _emit(component: str, message: str, *, session: Optional[str] = None, level: str = "info", force: bool = False) -> None:
    if level == "debug" and not (DEBUG_ENABLED or force):
        return
    prefix = _render_prefix(component, session=session, level=level)
    with _PRINT_LOCK:
        print(f"{prefix} {message}", flush=True)


def log_debug(component: str, message: str, *, session: Optional[str] = None, force: bool = False) -> None:
    _emit(component, message, session=session, level="debug", force=force)



def log_info(component: str, message: str, *, session: Optional[str] = None) -> None:
    _emit(component, message, session=session, level="info")



def log_error(component: str, message: str, *, session: Optional[str] = None) -> None:
    _emit(component, message, session=session, level="error")


# Backward-compatible wrapper so older code still works if any call remains.
def log_line(component: str, message: str, *, level: str = "info", force: bool = False) -> None:
    if level == "debug":
        log_debug(component, message, force=force)
    elif level == "error":
        log_error(component, message)
    else:
        log_info(component, message)



def human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    v = float(max(0, n))
    i = 0
    while v >= 1024 and i < len(units) - 1:
        v /= 1024.0
        i += 1
    return f"{int(v)} {units[i]}" if i == 0 else f"{v:.2f} {units[i]}"



def human_duration(seconds: float | int) -> str:
    s = int(max(0, seconds))
    m, sec = divmod(s, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {sec}s"
    if m:
        return f"{m}m {sec}s"
    return f"{sec}s"



def now_ts() -> str:
    return time.strftime("%H:%M:%S")
