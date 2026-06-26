"""Bake the directory server URL and pinned signing public key into a single
client config file: directory_config.json.

This is what the user runs once after dropping the client code onto a new
machine (laptop, workstation, contributor box). After this completes, the
client knows where the directory server is and which signing key to trust;
end users never have to type a URL into the popup.

Usage:
    python tools/install_client.py http://your-directory.example:7071

Or with the URL preset:
    SP_DIRECTORY_SERVER_URL=http://your-directory.example:7071 \
        python tools/install_client.py

The tool fetches the directory server's signing public key over HTTP from
the new /signing-key endpoint. This is Trust-On-First-Use bootstrap. Once
the key is pinned, all subsequent /directory responses must verify against
it — a different key (forged or new) will be rejected.

To rotate (e.g. after the directory server regenerated its key), simply
re-run this tool and it will replace the pinned key, with a confirmation
prompt before doing so.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

CONFIG_PATH = PROJECT_ROOT / "directory_config.json"


def _resolve_url() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1].strip().rstrip("/")
    return os.getenv("SP_DIRECTORY_SERVER_URL", "").strip().rstrip("/")


def _read_existing_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _fetch_signing_key(url: str) -> str:
    print(f"Fetching signing key from {url}/signing-key ...")
    # Bypass system HTTP proxy: if the user already has 127.0.0.1:8080
    # configured as their system proxy from a previous run, urllib would
    # try to route this fetch through the local onion proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url + "/signing-key", timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        print(f"  Failed to reach the directory server: {exc}")
        sys.exit(1)
    key = str(payload.get("signing_public_key_b64") or "").strip()
    if not key or len(key) < 20:
        print(f"  Server did not return a valid signing key. Response was: {payload}")
        sys.exit(1)
    return key


def main() -> None:
    url = _resolve_url()
    if not url:
        print("Error: no directory server URL provided.")
        print(__doc__)
        sys.exit(2)

    new_key = _fetch_signing_key(url)
    existing = _read_existing_config()
    existing_key = str(existing.get("directory_signing_pub_key_b64") or "").strip()
    existing_url = str(existing.get("directory_server_url") or "").strip().rstrip("/")

    if existing_key and existing_key == new_key and existing_url == url:
        print(f"\nConfig already matches:")
        print(f"  url: {url}")
        print(f"  key: {new_key[:32]}...")
        print(f"\nNo change needed.")
        return

    if existing_key and existing_key != new_key:
        print(f"\nWarning: replacing existing pinned key.")
        print(f"  old: {existing_key}")
        print(f"  new: {new_key}")
        print()
        print(f"This means the directory server's key changed. If you didn't")
        print(f"expect that, an attacker may be impersonating the server.")
        print(f"Press Enter to continue, Ctrl+C to abort.")
        try:
            input()
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(1)

    config = {
        "directory_server_url": url,
        "directory_signing_pub_key_b64": new_key,
    }
    with CONFIG_PATH.open("w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")

    print(f"\nWrote {CONFIG_PATH}:")
    print(f"  directory_server_url: {url}")
    print(f"  directory_signing_pub_key_b64: {new_key[:32]}... ({len(new_key)} chars)")

    # If this machine has the directory server's private signing key, it IS
    # the directory server. Removing its directory.json would break it. So
    # we keep all server-side files in that case and just write
    # directory_config.json (which is a no-op for the server's own logic
    # but lets the proxy_client running on the same machine resolve the
    # URL through the normal client path).
    server_key = PROJECT_ROOT / "directory_signing_key.json"
    is_directory_server = server_key.exists()

    if is_directory_server:
        print(f"\nThis machine appears to BE the directory server (found "
              f"{server_key.name}). Keeping directory.json and other server "
              f"files intact. directory_config.json was added so the local "
              f"proxy_client can resolve the URL automatically.")
    else:
        # End-user clients should not have a local directory.json. The relay
        # topology must come from the live signed directory, not from a
        # bundled snapshot. Remove any leftover file so we never bootstrap
        # from it.
        legacy_paths = [
            PROJECT_ROOT / "directory.json",
            PROJECT_ROOT / "directory_signing_pub.txt",
            PROJECT_ROOT / "directory_server_url.txt",
        ]
        removed = []
        for p in legacy_paths:
            if p.exists():
                try:
                    p.unlink()
                    removed.append(p.name)
                except Exception as exc:
                    print(f"  Note: could not remove {p.name}: {exc}")
        if removed:
            print(f"\nRemoved client-side stale files: {', '.join(removed)}")
            print("  (the live directory server is now the only source of relay info)")

    print(f"\nThe client is now configured. Start proxy_client and the popup will")
    print(f"connect to the directory server automatically. No further configuration is needed.")


if __name__ == "__main__":
    main()
