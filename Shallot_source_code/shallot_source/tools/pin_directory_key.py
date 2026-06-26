"""Pin (or re-pin) the directory server's signing public key on this machine.

Use this when:
  * You set up a new client/relay/contributor machine and need to pin the key.
  * Your `directory_signing_pub.txt` is stale (e.g. the directory server
    regenerated its signing key) and the client now rejects every directory
    response with `signature_mismatch_check_pinned_key`.

Run on the CLIENT machine (not the directory server) from the project root:
    python tools/pin_directory_key.py http://192.168.1.168:7071

Or with the SP_DIRECTORY_SERVER_URL env var set:
    python tools/pin_directory_key.py

This is a Trust-On-First-Use bootstrap: anyone on the network could intercept
this request and pin a malicious key. For a real deployment, copy the file
`directory_signing_pub.txt` directly from the directory-server machine over a
trusted channel instead of running this tool.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from shared.key_exchange import DIRECTORY_SIGNING_PUB_PATH, load_pinned_directory_signing_pub_key


def main() -> None:
    url = ""
    if len(sys.argv) > 1:
        url = sys.argv[1].strip().rstrip("/")
    else:
        url = os.getenv("SP_DIRECTORY_SERVER_URL", "").strip().rstrip("/")

    if not url:
        print("Error: no directory server URL provided.")
        print(__doc__)
        sys.exit(2)

    print(f"Fetching signing key from {url}/signing-key ...")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url + "/signing-key", timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        print(f"Failed to reach the directory server: {exc}")
        sys.exit(1)

    new_key = str(payload.get("signing_public_key_b64") or "").strip()
    if not new_key or len(new_key) < 20:
        print(f"Server response did not include a valid signing key: {payload}")
        sys.exit(1)

    existing = load_pinned_directory_signing_pub_key()
    if existing and existing == new_key:
        print(f"Pinned key already matches the server. No change.")
        print(f"  Path: {DIRECTORY_SIGNING_PUB_PATH}")
        return

    if existing:
        print(f"Replacing existing pinned key:")
        print(f"  old: {existing}")
        print(f"  new: {new_key}")
        print()
        print(f"WARNING: This means the directory server's signing key changed.")
        print(f"If you didn't expect that, an attacker may be impersonating the")
        print(f"directory server. Press Ctrl+C now to abort, or Enter to continue.")
        try:
            input()
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(1)

    DIRECTORY_SIGNING_PUB_PATH.parent.mkdir(parents=True, exist_ok=True)
    DIRECTORY_SIGNING_PUB_PATH.write_text(new_key + "\n", encoding="utf-8")
    print(f"\nPinned key written to {DIRECTORY_SIGNING_PUB_PATH}")
    print("You can now restart your relay/client; signed-directory verification will work.")


if __name__ == "__main__":
    main()
