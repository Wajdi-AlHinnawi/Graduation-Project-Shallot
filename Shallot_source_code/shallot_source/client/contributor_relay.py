"""Local contributor relay service.

When a user enables "Contribute as Middle Relay", the local client starts a
middle relay on the user's machine and registers it with the directory server.
Other clients can then select this relay as one of the contributor hops in
Contributor Path mode.

Registrations, heartbeats, and unregister calls are now signed with the
contributor's own Ed25519 signing key so that a third party cannot hijack
this contributor's slot in the directory.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import socket
import time
import urllib.request
from pathlib import Path
from typing import Optional

from relays.relay_common import decrypt_relay_layer, decrypt_relay_layer_with_key, relay_packet, make_connection_limiter
from shared.config import CONTRIBUTOR_DEFAULT_PORT, CONTRIBUTOR_HEARTBEAT_INTERVAL_SECONDS
from shared.key_exchange import (
    get_local_public_key_b64,
    get_relay_signing_public_key_b64,
    sign_with_relay_key,
)
from shared.logging_utils import log_error, log_info
from shared.protocol import recv_json, send_json, safe_close_writer, padding_cell_size_from_message


def _canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIRECTORY_PATH = PROJECT_ROOT / "directory.json"

_CONTRIB_SERVER: Optional[asyncio.base_events.Server] = None
_CONTRIB_RELAY_ID: Optional[str] = None
_CONTRIB_HOST: Optional[str] = None
_CONTRIB_PORT: Optional[int] = None
_CONTRIB_DIRECTORY_URL: Optional[str] = None
_HEARTBEAT_TASK: Optional[asyncio.Task] = None
_CONN_LIMITER = make_connection_limiter()


def _detect_local_lan_ip() -> str:
    """Return the IP of the network interface used to reach the internet.

    This is the legacy auto-detect: connect a UDP socket to a public IP
    (8.8.8.8) and read what the OS picked as the source address. Behind
    NAT this returns the host's RFC1918 LAN address (e.g. 192.168.1.x).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


# Lookups used by detect_lan_ip when public-IP auto-detect is enabled.
# Ordered by reliability/speed; we stop at the first one that returns a
# plausible IPv4 address. Each lookup is bounded by a short timeout so a
# slow service does not stall contributor startup.
_PUBLIC_IP_LOOKUP_URLS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)
_PUBLIC_IP_LOOKUP_TIMEOUT_SECONDS = 3
_PUBLIC_IP_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$")
# Bypass any system HTTP proxy so the lookup never tries to traverse the
# local onion proxy at 127.0.0.1:8080.
_PUBLIC_IP_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# RFC6598 carrier-grade NAT range. ipaddress.IPv4Address does not flag
# this as private, but a CGNAT address advertised to other relays would
# fail to accept inbound connections just like an RFC1918 address would,
# so we reject it explicitly. If a public-IP lookup ever returns one,
# the caller is almost certainly on a CGNAT residential/mobile link and
# the network's NAT-traversal limitation should be surfaced rather than
# papered over with a non-routable address.
_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")


def _looks_like_routable_public_ipv4(text: str) -> str | None:
    """Validate that `text` is a routable public IPv4 string.

    Rejects anything that is not a clean IPv4 address, plus addresses that
    fall in private/reserved ranges (RFC1918, loopback, link-local, CGNAT,
    documentation, multicast, etc.). If the lookup service ever returned
    one of these, advertising it as the contributor's public address would
    be just as broken as the LAN auto-detect we're trying to replace.
    """
    match = _PUBLIC_IP_RE.match(text or "")
    if not match:
        return None
    candidate = match.group(1)
    try:
        addr = ipaddress.IPv4Address(candidate)
    except ValueError:
        return None
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or addr in _CGNAT_NETWORK
    ):
        return None
    return candidate


def _detect_public_ip() -> str | None:
    """Best-effort public IP lookup. Returns None if every service fails or
    if the candidate they return is not a routable public IPv4 address.

    This makes `auto` mode in the popup do the right thing for the common
    case: a user behind home NAT enables Contribute, and the directory
    receives their public IP rather than their LAN address. Users on a
    purely private testbed (no internet access to these services) fall
    through to the LAN-IP auto-detect, which preserves the previous
    behavior for that case.
    """
    for url in _PUBLIC_IP_LOOKUP_URLS:
        try:
            with _PUBLIC_IP_OPENER.open(url, timeout=_PUBLIC_IP_LOOKUP_TIMEOUT_SECONDS) as response:
                raw = response.read().decode("utf-8", errors="ignore")
        except Exception as exc:
            log_info("CONTRIB", f"Public IP lookup failed via {url}: {exc}")
            continue
        candidate = _looks_like_routable_public_ipv4(raw)
        if candidate:
            log_info("CONTRIB", f"Public IP auto-detected as {candidate} (source: {url})")
            return candidate
        log_info("CONTRIB", f"Public IP lookup via {url} returned non-public value, skipping")
    return None


def detect_lan_ip() -> str:
    """Pick the IP this contributor advertises to other clients.

    Resolution order:
      1. SP_CONTRIBUTOR_PUBLIC_HOST env var, if set (operator override).
      2. SP_CONTRIBUTOR_AUTO_DETECT_PUBLIC=0 disables the public-IP lookup,
         falling straight through to the LAN-IP auto-detect. Useful for
         purely private testbeds where every relay is on the same LAN
         and outbound HTTPS to api.ipify.org is unwanted.
      3. Public-IP auto-detect via small public services (api.ipify.org,
         ifconfig.me, icanhazip.com), bounded by short timeouts. This
         covers the common case of a user behind home NAT who clicks
         "Contribute" without typing an IP into the popup. Without this
         step, the LAN auto-detect would advertise an RFC1918 address
         (e.g. 192.168.1.x), which other relays cannot reach.
      4. LAN auto-detect, the original behavior. Used when public lookup
         is disabled, fails, or returns a non-routable address.

    The function name is kept for backwards compatibility with existing
    callers; despite the historical name, the value returned is now the
    contributor's best-known publicly reachable address whenever one can
    be determined.
    """
    configured = os.getenv("SP_CONTRIBUTOR_PUBLIC_HOST", "").strip()
    if configured:
        return configured

    auto_public = os.getenv("SP_CONTRIBUTOR_AUTO_DETECT_PUBLIC", "1").strip().lower()
    if auto_public not in {"0", "false", "no", "off"}:
        public = _detect_public_ip()
        if public:
            return public
        log_info("CONTRIB", "Public IP auto-detect failed; falling back to LAN auto-detect.")

    return _detect_local_lan_ip()


def _hostname_slug() -> str:
    raw = socket.gethostname().lower()
    return "".join(ch if ch.isalnum() else "-" for ch in raw).strip("-") or "user"


def _load_directory_payload() -> dict:
    """Load the local directory.json if present.

    On client/contributor machines (which do not ship with directory.json
    in the new install model), this returns an empty payload. The local
    write is just a convenience for the legacy single-machine setup where
    the directory server and the contributor share a project root; it is
    not authoritative. Authoritative state lives on the directory server,
    which the contributor reaches via HTTP register/heartbeat calls.
    """
    if not DIRECTORY_PATH.exists():
        return {"relays": []}
    try:
        with DIRECTORY_PATH.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {"relays": []}


def _save_directory_payload(payload: dict) -> None:
    """Write the directory payload only if a directory.json already exists.

    On a fresh client install we deliberately skip this so that the client
    does not start materializing a stale local snapshot. The directory
    server holds the canonical state.
    """
    if not DIRECTORY_PATH.exists():
        return
    try:
        with DIRECTORY_PATH.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
    except Exception:
        pass


def _upsert_local_contributor(relay_id: str, host: str, port: int) -> dict:
    os.environ["SP_LOCAL_RELAY_ID"] = relay_id
    os.environ.setdefault("SP_CONTRIBUTOR_RELAY_ID", relay_id)
    payload = _load_directory_payload()
    relays = payload.setdefault("relays", [])
    item = None
    for candidate in relays:
        if candidate.get("id") == relay_id:
            item = candidate
            break
    if item is None:
        item = {"id": relay_id}
        relays.append(item)
    item.update({
        "id": relay_id,
        "role": "middle",
        "host": host,
        "port": int(port),
        "enabled": True,
        "official": False,
        "contributor": True,
        "status": "online",
    })
    _save_directory_payload(payload)

    public_key = get_local_public_key_b64(relay_id)
    item["public_key_b64"] = public_key
    _save_directory_payload(payload)
    return item


def _directory_server_url(override: str | None = None) -> str:
    raw = (override or _CONTRIB_DIRECTORY_URL or os.getenv("SP_DIRECTORY_SERVER_URL", "")).strip().rstrip("/")
    return raw


# Bypass any system HTTP proxy when talking to the directory server (see
# explanation in shared/security.py and shared/relay_registration.py).
_DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with _DIRECT_OPENER.open(req, timeout=5) as response:
        return json.loads(response.read().decode("utf-8") or "{}")


def _build_signed_registration(relay: dict) -> dict:
    """Build a registration payload with a self-signature from the relay's signing key.

    The directory server will verify this signature against the
    signing_public_key_b64 in the same payload. On subsequent heartbeats,
    the server checks the request signature against the registered key,
    so only this machine (which holds the private signing key) can update
    or remove the registration.
    """
    relay_id = relay["id"]
    body = {
        "id": relay_id,
        "host": relay["host"],
        "port": int(relay["port"]),
        "public_key_b64": relay["public_key_b64"],
        "signing_public_key_b64": get_relay_signing_public_key_b64(relay_id),
        "ts": int(time.time()),
    }
    body["signature_b64"] = sign_with_relay_key(relay_id, _canonical_json(body))
    return body


def register_with_directory_server(relay: dict, directory_server_url: str | None = None) -> dict:
    url = _directory_server_url(directory_server_url)
    if not url:
        return {"ok": True, "registered": False, "reason": "no_directory_server_configured"}
    signed = _build_signed_registration(relay)
    return _post_json(url + "/register-contributor", signed)


def heartbeat_directory_server(relay_id: str) -> dict:
    url = _directory_server_url()
    if not url:
        return {"ok": True, "heartbeat": False, "reason": "no_directory_server_configured"}
    ts = int(time.time())
    body = {"id": relay_id, "ts": ts, "kind": "heartbeat"}
    payload = {
        "id": relay_id,
        "ts": ts,
        "signature_b64": sign_with_relay_key(relay_id, _canonical_json(body)),
    }
    return _post_json(url + "/heartbeat-contributor", payload)


def unregister_from_directory_server(relay_id: str) -> dict:
    url = _directory_server_url()
    if not url:
        return {"ok": True, "registered": False, "reason": "no_directory_server_configured"}
    ts = int(time.time())
    body = {"id": relay_id, "ts": ts, "kind": "unregister"}
    payload = {
        "id": relay_id,
        "ts": ts,
        "signature_b64": sign_with_relay_key(relay_id, _canonical_json(body)),
    }
    return _post_json(url + "/unregister-contributor", payload)


async def _heartbeat_loop(relay_id: str) -> None:
    while True:
        await asyncio.sleep(CONTRIBUTOR_HEARTBEAT_INTERVAL_SECONDS)
        try:
            result = await asyncio.to_thread(heartbeat_directory_server, relay_id)
            if not result.get("ok"):
                log_error("CONTRIB", f"Heartbeat failed: {result}")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log_error("CONTRIB", f"Heartbeat error: {exc}")


async def _handle_contributor_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    relay_id = _CONTRIB_RELAY_ID or "contributor"
    tag = f"MIDDLE-{relay_id}"
    if not _CONN_LIMITER.check_rate_limit(peer):
        log_error(tag, f"Rate-limit reject from {peer}")
        try:
            await send_json(writer, {"ok": False, "error": "relay_error", "code": "rate_limited"})
        except Exception:
            pass
        await safe_close_writer(writer, tag, verbose=False)
        return

    async with _CONN_LIMITER.semaphore:
        quiet = False
        session = None
        response_cell_size = None
        try:
            message = await recv_json(reader)
            quiet = bool(message.get("quiet", False))
            response_cell_size = padding_cell_size_from_message(message)
            # Decrypt the layer once and pass it through to relay_packet so
            # we don't decrypt twice per forwarded packet.
            inner = None
            contrib_key = None
            if message.get("type") == "onion" and "layer_b64" in message:
                try:
                    inner, contrib_key = decrypt_relay_layer_with_key(message, relay_id, "middle")
                    session = inner.get("session_id")
                except Exception:
                    inner = None
                    contrib_key = None
                    session = None
            if not quiet:
                log_info(tag, f"Accepted packet from {peer}", session=session)

            if message.get("type") != "onion":
                await send_json(writer, {"ok": False, "error": "relay_error", "code": "unsupported_message_type"}, padded_cell_size=response_cell_size)
                return

            response = await relay_packet(message, tag, relay_id, "middle", inner=inner, relay_key=contrib_key)
            await send_json(writer, response, padded_cell_size=response_cell_size)
            if not quiet:
                log_info(tag, f"Response returned to previous hop | ok={response.get('ok', False)}", session=session)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log_error(tag, f"Server error: {exc}", session=session)
            try:
                await send_json(writer, {"ok": False, "error": "relay_error", "code": "relay_handler_error"}, padded_cell_size=response_cell_size)
            except Exception:
                pass
        finally:
            await safe_close_writer(writer, tag, verbose=False)


async def start_contributor_relay(public_host: str | None = None, port: int | None = None, relay_id: str | None = None, directory_server_url: str | None = None) -> dict:
    global _CONTRIB_SERVER, _CONTRIB_RELAY_ID, _CONTRIB_HOST, _CONTRIB_PORT, _CONTRIB_DIRECTORY_URL, _HEARTBEAT_TASK

    if _CONTRIB_SERVER is not None:
        return {
            "ok": True,
            "already_running": True,
            "relay_id": _CONTRIB_RELAY_ID,
            "host": _CONTRIB_HOST or public_host or detect_lan_ip(),
            "port": _CONTRIB_PORT,
            "directory_server_url": _CONTRIB_DIRECTORY_URL,
        }

    public_host = public_host or detect_lan_ip()
    port = int(port or os.getenv("SP_CONTRIBUTOR_PORT", str(CONTRIBUTOR_DEFAULT_PORT)))
    safe_host = public_host.replace(".", "-").replace(":", "-")
    relay_id = relay_id or os.getenv(
        "SP_CONTRIBUTOR_RELAY_ID",
        f"contrib-{_hostname_slug()}-{safe_host}-{port}"
    )
    _CONTRIB_DIRECTORY_URL = _directory_server_url(directory_server_url) or None
    if _CONTRIB_DIRECTORY_URL:
        os.environ["SP_DIRECTORY_SERVER_URL"] = _CONTRIB_DIRECTORY_URL

    relay = _upsert_local_contributor(relay_id, public_host, port)

    _CONTRIB_RELAY_ID = relay_id
    _CONTRIB_HOST = public_host
    _CONTRIB_PORT = port
    _CONTRIB_SERVER = await asyncio.start_server(_handle_contributor_client, "0.0.0.0", port)

    try:
        registry_result = await asyncio.to_thread(register_with_directory_server, relay, _CONTRIB_DIRECTORY_URL)
    except Exception as exc:
        registry_result = {"ok": False, "registered": False, "error": str(exc)}

    if _CONTRIB_DIRECTORY_URL:
        _HEARTBEAT_TASK = asyncio.create_task(_heartbeat_loop(relay_id))

    log_info("CONTRIB", f"Contributor middle relay listening on 0.0.0.0:{port} as {relay_id}")
    log_info("CONTRIB", f"Advertised contributor address: {public_host}:{port}")
    log_info("CONTRIB", f"Directory registration result: {registry_result}")

    return {
        "ok": True,
        "relay_id": relay_id,
        "host": public_host,
        "port": port,
        "relay": relay,
        "directory_server_url": _CONTRIB_DIRECTORY_URL,
        "directory_registration": registry_result,
    }


async def stop_contributor_relay() -> dict:
    global _CONTRIB_SERVER, _CONTRIB_RELAY_ID, _CONTRIB_HOST, _CONTRIB_PORT, _CONTRIB_DIRECTORY_URL, _HEARTBEAT_TASK
    relay_id = _CONTRIB_RELAY_ID

    if _HEARTBEAT_TASK is not None:
        _HEARTBEAT_TASK.cancel()
        try:
            await _HEARTBEAT_TASK
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
        _HEARTBEAT_TASK = None

    if _CONTRIB_SERVER is None:
        return {"ok": True, "stopped": False, "relay_id": relay_id}

    _CONTRIB_SERVER.close()
    await _CONTRIB_SERVER.wait_closed()
    _CONTRIB_SERVER = None
    _CONTRIB_PORT = None
    _CONTRIB_HOST = None

    registry_result = {}
    if relay_id:
        try:
            registry_result = await asyncio.to_thread(unregister_from_directory_server, relay_id)
        except Exception as exc:
            registry_result = {"ok": False, "error": str(exc)}

    log_info("CONTRIB", f"Contributor relay stopped: {relay_id}")
    _CONTRIB_RELAY_ID = None
    _CONTRIB_DIRECTORY_URL = None
    return {"ok": True, "stopped": True, "relay_id": relay_id, "directory_registration": registry_result}


def contributor_status() -> dict:
    return {
        "running": _CONTRIB_SERVER is not None,
        "relay_id": _CONTRIB_RELAY_ID,
        "host": _CONTRIB_HOST,
        "port": _CONTRIB_PORT,
        "directory_server_url": _CONTRIB_DIRECTORY_URL,
        "heartbeat_running": _HEARTBEAT_TASK is not None and not _HEARTBEAT_TASK.done(),
    }
