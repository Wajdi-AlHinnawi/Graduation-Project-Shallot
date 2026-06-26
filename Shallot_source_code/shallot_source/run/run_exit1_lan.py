import asyncio
import os
import socket
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ["RELAY_NAME"] = "exit1"
os.environ["RELAY_HOST"] = "0.0.0.0"
os.environ["RELAY_PORT"] = "9003"

# Tell the directory which address other machines (contributors) should use to
# reach this exit. Override by setting RELAY_PUBLIC_HOST in the environment;
# otherwise we auto-detect by opening a UDP socket to a public IP and reading
# the chosen source address (no traffic is actually sent).
def _autodetect_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return ""

if not os.environ.get("RELAY_PUBLIC_HOST"):
    detected = _autodetect_lan_ip()
    if detected and detected != "127.0.0.1":
        os.environ["RELAY_PUBLIC_HOST"] = detected
        print(f"[run_exit1_lan] Auto-detected LAN IP for directory advertisement: {detected}")

from relays.exit_relay import main

if __name__ == "__main__":
    asyncio.run(main())
