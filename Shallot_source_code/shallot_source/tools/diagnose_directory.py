"""Diagnose why the client isn't seeing contributors.

Run on the SAME machine your client is running on, with the SAME working directory
as the project. It will:
  1) Show whether SP_DIRECTORY_SERVER_URL is set
  2) Show whether you have a pinned directory_signing_pub.txt
  3) Try to fetch the directory and verify the signature
  4) List the contributors the directory says are online
  5) Compare the pinned key to the server's actual key

Usage (from the project root, on the client machine):
    python tools/diagnose_directory.py
or pass the URL explicitly:
    python tools/diagnose_directory.py http://192.168.1.168:7071
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from shared.key_exchange import (
    load_pinned_directory_signing_pub_key,
    verify_signature,
    DIRECTORY_SIGNING_PUB_PATH,
)


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main() -> None:
    print("=" * 60)
    print("Directory Diagnostic Tool")
    print("=" * 60)

    url = ""
    if len(sys.argv) > 1:
        url = sys.argv[1].strip().rstrip("/")
    else:
        url = os.getenv("SP_DIRECTORY_SERVER_URL", "").strip().rstrip("/")

    if not url:
        print("\n[FAIL] No directory server URL provided.")
        print("       Set SP_DIRECTORY_SERVER_URL or pass the URL as an argument.")
        print("       Example: python tools/diagnose_directory.py http://192.168.1.168:7071")
        return

    print(f"\nDirectory server URL: {url}")

    print(f"\nPinned key path: {DIRECTORY_SIGNING_PUB_PATH}")
    pinned = load_pinned_directory_signing_pub_key()
    if pinned:
        print(f"  Pinned key:   {pinned[:32]}... (length {len(pinned)})")
    else:
        print("  Pinned key:   <none> (will accept any signature in DEVELOPMENT mode)")

    print(f"\nFetching {url}/directory ...")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url + "/directory", timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        print(f"  [FAIL] Could not reach the directory server: {exc}")
        print(f"         Check that:")
        print(f"           - the directory_server.py process is running on the target machine")
        print(f"           - port 7071 is reachable from this machine (firewall, network)")
        print(f"           - the URL is correct")
        return

    print(f"  [OK]   Fetched directory payload ({len(json.dumps(payload))} bytes)")

    relays = payload.get("relays", [])
    print(f"\nDirectory contains {len(relays)} relays:")
    for r in relays:
        marker = "[contrib]" if r.get("contributor") else "[official]"
        status = r.get("status", "?")
        online = "online" if r.get("enabled") and status != "offline" else "OFFLINE"
        signing_pub = r.get("signing_public_key_b64", "<none>")
        print(f"  {marker:12s} {r.get('id','?'):40s} {r.get('host','?')}:{r.get('port','?'):<6} {online}")
        if signing_pub == "<none>":
            print("              ^^^ WARNING: this relay has no signing_public_key_b64; it pre-dates v4")

    contributors = [r for r in relays if r.get("contributor")]
    online_contributors = [r for r in contributors if r.get("enabled") and r.get("status") != "offline"]
    print(f"\nContributors: {len(contributors)} total, {len(online_contributors)} online")

    print("\nSignature verification:")
    if "signature_b64" not in payload:
        print("  [FAIL] Response has NO signature field. The directory server may be older than v4.")
        return
    print(f"  signature_b64: {payload['signature_b64'][:32]}... (length {len(payload['signature_b64'])})")
    print(f"  issued_at:     {payload.get('issued_at')}")
    print(f"  max_age_seconds: {payload.get('max_age_seconds')}")

    if pinned:
        body = {"relays": payload.get("relays", []), "issued_at": int(payload.get("issued_at") or 0)}
        ok = verify_signature(pinned, canonical_json(body), payload["signature_b64"])
        if ok:
            print(f"  [OK]   Signature is valid against your pinned key.")
        else:
            print(f"  [FAIL] Signature does NOT match your pinned key.")
            print(f"         This means your `directory_signing_pub.txt` does not match the directory server's key.")
            print(f"         Likely cause: the directory server regenerated its key, or you copied an old copy.")
            print(f"         Fix: on the directory-server machine, find `directory_signing_pub.txt` and copy it")
            print(f"              to this machine, replacing the file at {DIRECTORY_SIGNING_PUB_PATH}.")
            print(f"         Or: run `python tools/pin_directory_key.py {url}` to TOFU-pin the server's current key.")
    else:
        print("  (no pinned key, signature would not be checked by the running client)")

    print("\nIf your dashboard says 'Online Contributors: 0' but the count above is > 0, the most")
    print("likely cause is that your proxy_client process can't fetch this URL (firewall, env var)")
    print("or the signature verification is failing (see above).")


if __name__ == "__main__":
    main()
