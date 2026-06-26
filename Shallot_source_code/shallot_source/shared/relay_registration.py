"""Signed relay registration/heartbeat helper.

Used by both:
  - official relay startup (entry/middle/exit) via /register-relay + /heartbeat-relay
  - contributor relay startup via /register-contributor + /heartbeat-contributor

The directory server holds only public information (host, port, public keys)
that the relay itself sends in. Every registration and heartbeat is signed
with the relay's own Ed25519 key, and the directory server enforces that
once a relay ID is registered, only the holder of the matching private key
can update or replace it (anti-hijack).
"""
from __future__ import annotations

import asyncio
import json
import time
import urllib.error
import urllib.request

from shared.config import CONTRIBUTOR_HEARTBEAT_INTERVAL_SECONDS
from shared.key_exchange import (
    ensure_local_relay_key,
    get_relay_signing_public_key_b64,
    sign_with_relay_key,
)
from shared.logging_utils import log_error, log_info
from shared.security import get_directory_server_url


def _canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# Bypass any system HTTP proxy when talking to the directory server. On
# Windows, if the user has set the system proxy to 127.0.0.1:8080 (the
# local onion proxy), an unconfigured urlopen would route registration
# requests THROUGH the local onion proxy, which would fail. Direct only.
_DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _post_json(url: str, payload: dict, timeout: int = 5) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _DIRECT_OPENER.open(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8") or "{}")
        except Exception:
            body = {"error": f"HTTP {exc.code}"}
        return {"ok": False, "registered": False, "heartbeat": False, **body}
    except Exception as exc:
        return {"ok": False, "registered": False, "heartbeat": False, "error": str(exc)}


def build_signed_registration(relay_id: str, host: str, port: int, public_key_b64: str) -> dict:
    """Build a self-signed registration payload for a relay.

    Generates the ts, signs the canonical body with the relay's Ed25519 key,
    and returns the dict ready to POST.
    """
    body = {
        "id": relay_id,
        "host": host,
        "port": int(port),
        "public_key_b64": public_key_b64,
        "signing_public_key_b64": get_relay_signing_public_key_b64(relay_id),
        "ts": int(time.time()),
    }
    body["signature_b64"] = sign_with_relay_key(relay_id, _canonical_json(body))
    return body


def build_signed_heartbeat(relay_id: str) -> dict:
    """Build a signed heartbeat payload for a relay."""
    ts = int(time.time())
    body = {"id": relay_id, "ts": ts, "kind": "heartbeat"}
    return {
        "id": relay_id,
        "ts": ts,
        "signature_b64": sign_with_relay_key(relay_id, _canonical_json(body)),
    }


def register_official_relay(relay_id: str, host: str, port: int, directory_url: str | None = None) -> dict:
    """POST /register-relay — synchronous, blocking. Call from a worker thread
    if invoked from an asyncio coroutine.
    """
    url = (directory_url or get_directory_server_url()).strip().rstrip("/")
    if not url:
        return {"ok": False, "registered": False, "error": "no_directory_server_url_configured"}
    record = ensure_local_relay_key(relay_id, update_directory=False)
    body = build_signed_registration(relay_id, host, port, record["public_key_b64"])
    return _post_json(url + "/register-relay", body)


def heartbeat_official_relay(relay_id: str, directory_url: str | None = None) -> dict:
    """POST /heartbeat-relay — synchronous, blocking."""
    url = (directory_url or get_directory_server_url()).strip().rstrip("/")
    if not url:
        return {"ok": False, "heartbeat": False, "error": "no_directory_server_url_configured"}
    body = build_signed_heartbeat(relay_id)
    return _post_json(url + "/heartbeat-relay", body)


async def run_official_relay_registration_loop(
    relay_id: str,
    public_host: str,
    port: int,
    role: str = "relay",
) -> None:
    """Background coroutine: register at startup, then heartbeat forever.

    Logs once on first successful registration and once on each transition
    between healthy and unhealthy state. Keeps quiet otherwise.
    """
    tag = f"{role.upper()}-{relay_id}"
    last_state: str | None = None
    interval = max(5, int(CONTRIBUTOR_HEARTBEAT_INTERVAL_SECONDS))

    # First call is a registration; subsequent are heartbeats.
    while True:
        if last_state in (None, "unregistered"):
            result = await asyncio.to_thread(register_official_relay, relay_id, public_host, port)
            if result.get("ok"):
                if last_state != "registered":
                    log_info(tag, f"Registered with directory server at {public_host}:{port}")
                    last_state = "registered"
            else:
                if last_state != "unregistered":
                    log_error(tag, f"Could not register with directory server: {result.get('error', 'unknown')}. Will retry.")
                    last_state = "unregistered"
        else:
            result = await asyncio.to_thread(heartbeat_official_relay, relay_id)
            if result.get("ok"):
                # Stay registered; nothing to log on each heartbeat.
                pass
            else:
                # If heartbeat fails because the directory server lost our
                # entry (e.g. it restarted or pruned us), drop back to
                # registration mode on the next cycle.
                err = str(result.get("error", "")).lower()
                if "not_found" in err or "no_registered_signing_key" in err:
                    if last_state != "unregistered":
                        log_error(tag, f"Heartbeat says we are not registered ({result.get('error')}); will re-register.")
                        last_state = "unregistered"
                else:
                    log_error(tag, f"Heartbeat error: {result.get('error', 'unknown')}")

        await asyncio.sleep(interval)
