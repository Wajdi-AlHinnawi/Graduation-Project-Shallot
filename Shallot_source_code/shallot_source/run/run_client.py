import asyncio
import sys
from pathlib import Path

# Always run from project root imports, even when launched by IDEs like Eclipse.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.security import get_or_create_control_token, CONTROL_TOKEN_JS_FILE, CONTROL_TOKEN_FILE


def prepare_extension_control_token() -> None:
    """Create/update extension/control_token.js before the client starts.

    The Control API requires a Bearer token. The unpacked browser extension
    cannot read control_token_dev.txt from the project root, so we generate a
    JavaScript file inside the extension folder and load it before popup.js.
    """
    token = get_or_create_control_token()
    print(f"[CONTROL] Token file: {CONTROL_TOKEN_FILE}", flush=True)
    print(f"[CONTROL] Extension token JS: {CONTROL_TOKEN_JS_FILE}", flush=True)
    print("[CONTROL] If the extension was already open, reload it from edge://extensions or chrome://extensions.", flush=True)
    if not token:
        raise RuntimeError("Failed to create control API token")


from client.proxy_client import main


if __name__ == "__main__":
    prepare_extension_control_token()
    asyncio.run(main())
