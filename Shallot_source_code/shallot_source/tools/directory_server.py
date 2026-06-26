"""Development directory server for official relays and contributor relays.

Contributor relays register as middle-only nodes. They send heartbeats so the
server can mark stale contributors offline and eventually remove them.

Security:
* The directory server signs every /directory response with its Ed25519 key.
  Clients pin the corresponding public key via directory_signing_pub.txt.
* Contributor registrations must include a signature over the canonical
  registration body, made with the contributor's own Ed25519 signing key
  (whose public half is registered in the same call). This prevents anyone
  else from later hijacking a contributor's slot since the registered
  signing public key is required to authenticate heartbeats and unregister
  calls.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import time
from pathlib import Path
from urllib.parse import urlparse

from shared.config import (
    DIRECTORY_SERVER_HOST,
    DIRECTORY_SERVER_PORT,
    CONTRIBUTOR_OFFLINE_AFTER_SECONDS,
    CONTRIBUTOR_REMOVE_AFTER_SECONDS,
    DIRECTORY_RESPONSE_MAX_AGE_SECONDS,
)
from shared.logging_utils import log_error, log_info
from shared.key_exchange import (
    ensure_directory_signing_key,
    get_directory_signing_private_key,
    verify_signature,
    b64e,
)


def canonical_json(obj) -> bytes:
    """Deterministic JSON serialization for signing/verification."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIRECTORY_PATH = PROJECT_ROOT / "directory.json"
_ID_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,80}$")
_HOST_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,253}$")


def now() -> float:
    return time.time()


def load_payload() -> dict:
    with DIRECTORY_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    payload.setdefault("relays", [])
    return payload


def save_payload(payload: dict) -> None:
    # Atomic write: serialize to a temp file in the same directory, then
    # rename onto the target. If the process crashes mid-write, the
    # original directory.json is preserved intact instead of being left
    # half-written. Same pattern used in shared/security.py.
    DIRECTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = DIRECTORY_PATH.with_suffix(DIRECTORY_PATH.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    tmp.replace(DIRECTORY_PATH)


def _prune_payload(payload: dict) -> tuple[int, int]:
    changed_offline = 0
    removed = 0
    cutoff_offline = now() - CONTRIBUTOR_OFFLINE_AFTER_SECONDS
    cutoff_remove = now() - CONTRIBUTOR_REMOVE_AFTER_SECONDS
    kept = []
    for relay in payload.get("relays", []):
        if relay.get("contributor"):
            last_seen = float(relay.get("last_seen") or 0)
            # Any contributor without a `last_seen` could not have come from a
            # live POST /register-contributor call. It must have been baked
            # into directory.json by accident. Drop it: contributors only
            # become real via the signed registration flow.
            if last_seen <= 0:
                removed += 1
                continue
            if last_seen < cutoff_remove:
                removed += 1
                continue
            if last_seen < cutoff_offline:
                if relay.get("status") != "offline" or relay.get("enabled"):
                    changed_offline += 1
                relay["status"] = "offline"
                relay["enabled"] = False
        elif relay.get("official"):
            # Official relays are NEVER removed (their identity comes from
            # the operator's directory.json topology spec). But if they
            # stop sending heartbeats they get marked offline so clients
            # do not try to route through a dead relay.
            #
            # An official relay with no last_seen yet is one that has not
            # registered since the directory server started — it is also
            # marked offline and has no public_key/host info, so clients
            # will skip it during circuit selection.
            last_seen = float(relay.get("last_seen") or 0)
            if last_seen <= 0 or last_seen < cutoff_offline:
                if relay.get("status") != "offline" or relay.get("enabled"):
                    changed_offline += 1
                relay["status"] = "offline"
                relay["enabled"] = False
        kept.append(relay)
    payload["relays"] = kept
    return changed_offline, removed


def load_clean_payload() -> dict:
    payload = load_payload()
    offline, removed = _prune_payload(payload)
    if offline or removed:
        save_payload(payload)
        log_info("DIR", f"Contributor cleanup: marked_offline={offline}, removed={removed}")
    return payload


def http_json(status_code: int, payload: dict) -> bytes:
    body = json.dumps(payload, indent=2).encode("utf-8")
    reason = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed"}.get(status_code, "OK")
    headers = [
        f"HTTP/1.1 {status_code} {reason}",
        "Content-Type: application/json; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "Access-Control-Allow-Origin: *",
        "Access-Control-Allow-Methods: GET, POST, OPTIONS",
        "Access-Control-Allow-Headers: Content-Type",
        "",
        "",
    ]
    return "\r\n".join(headers).encode("utf-8") + body


async def read_request(reader: asyncio.StreamReader):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = await reader.read(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 1024 * 1024:
            raise ValueError("request_too_large")
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    if not lines or len(lines[0].split()) < 3:
        raise ValueError("invalid_request")
    method, path, _version = lines[0].split(maxsplit=2)
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    content_length = int(headers.get("content-length", "0"))
    body = rest
    while len(body) < content_length:
        chunk = await reader.read(content_length - len(body))
        if not chunk:
            break
        body += chunk
    return method.upper(), urlparse(path).path, body


def _validate_host(host: str) -> None:
    if not host or not _HOST_RE.match(host) or any(ch in host for ch in " /\\,@%"):
        raise ValueError("invalid_host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        # Hostname is allowed for VPS deployments.
        pass


def _validate_registration(item: dict) -> tuple[str, str, int, str, str]:
    relay_id = str(item.get("id") or "").strip()
    host = str(item.get("host") or "").strip()
    public_key = str(item.get("public_key_b64") or "").strip()
    signing_public_key = str(item.get("signing_public_key_b64") or "").strip()
    port = int(item.get("port") or 0)
    if not _ID_RE.match(relay_id):
        raise ValueError("invalid_relay_id")
    _validate_host(host)
    if not public_key or len(public_key) < 20:
        raise ValueError("invalid_public_key")
    if not signing_public_key or len(signing_public_key) < 20:
        raise ValueError("invalid_signing_public_key")
    if not (1 <= port <= 65535):
        raise ValueError("invalid_port")
    return relay_id, host, port, public_key, signing_public_key


def _registration_signed_body(item: dict) -> bytes:
    """Return the canonical bytes that a registration signature must cover."""
    body = {
        "id": str(item.get("id") or "").strip(),
        "host": str(item.get("host") or "").strip(),
        "port": int(item.get("port") or 0),
        "public_key_b64": str(item.get("public_key_b64") or "").strip(),
        "signing_public_key_b64": str(item.get("signing_public_key_b64") or "").strip(),
        "ts": int(item.get("ts") or 0),
    }
    return canonical_json(body)


def _verify_registration_signature(item: dict) -> None:
    """Verify the contributor's self-signature on the registration body.

    The signing public key in the body must match the signature. We also reject
    timestamps older than the configured drift window so stale registrations
    cannot be replayed.
    """
    signing_pub = str(item.get("signing_public_key_b64") or "").strip()
    signature = str(item.get("signature_b64") or "").strip()
    ts = int(item.get("ts") or 0)
    if not signature:
        raise ValueError("missing_registration_signature")
    if abs(time.time() - ts) > 60:
        raise ValueError("registration_timestamp_out_of_window")
    if not verify_signature(signing_pub, _registration_signed_body(item), signature):
        raise ValueError("invalid_registration_signature")


def _heartbeat_signed_body(relay_id: str, ts: int) -> bytes:
    return canonical_json({"id": relay_id, "ts": int(ts), "kind": "heartbeat"})


def _unregister_signed_body(relay_id: str, ts: int) -> bytes:
    return canonical_json({"id": relay_id, "ts": int(ts), "kind": "unregister"})


def _find_contributor(payload: dict, relay_id: str) -> dict | None:
    for relay in payload.get("relays", []):
        if relay.get("id") == relay_id and relay.get("contributor"):
            return relay
    return None


def _find_official(payload: dict, relay_id: str) -> dict | None:
    for relay in payload.get("relays", []):
        if relay.get("id") == relay_id and relay.get("official") and not relay.get("contributor"):
            return relay
    return None


def upsert_official_relay(item: dict) -> dict:
    """Register an official relay's host + public keys.

    Unlike contributors, an official relay's ID and role are fixed in the
    operator's directory.json topology spec. This handler does NOT create
    new official entries; it only updates the host and public keys for an
    ID that the operator has already declared. If an unknown official ID
    tries to register, we reject — that prevents an attacker who learns
    the registration protocol from injecting an arbitrary "official" relay
    into the directory.

    Anti-hijack works the same way as for contributors: once an official
    relay registers a signing key, only the holder of the matching private
    key can update or replace it.
    """
    relay_id, host, port, public_key, signing_public_key = _validate_registration(item)
    _verify_registration_signature(item)

    payload = load_clean_payload()
    existing = _find_official(payload, relay_id)
    if existing is None:
        raise PermissionError("official_relay_id_not_in_topology")

    # Port in the registration MUST match the port the operator declared.
    declared_port = int(existing.get("port") or 0)
    if declared_port and declared_port != port:
        raise PermissionError("official_relay_port_mismatch")

    prior_signing_pub = str(existing.get("signing_public_key_b64") or "").strip()
    if prior_signing_pub and prior_signing_pub != signing_public_key:
        raise PermissionError("official_relay_id_owned_by_different_signing_key")

    existing["host"] = host
    existing["port"] = port
    existing["public_key_b64"] = public_key
    existing["signing_public_key_b64"] = signing_public_key
    existing["enabled"] = True
    existing["status"] = "online"
    existing["last_seen"] = now()
    save_payload(payload)
    return existing


def heartbeat_official_relay(item: dict) -> dict:
    relay_id = str(item.get("id") or "").strip()
    ts = int(item.get("ts") or 0)
    signature = str(item.get("signature_b64") or "").strip()
    if not _ID_RE.match(relay_id):
        raise ValueError("invalid_relay_id")
    if abs(time.time() - ts) > 60:
        raise ValueError("heartbeat_timestamp_out_of_window")
    payload = load_clean_payload()
    found = _find_official(payload, relay_id)
    if found is None:
        raise ValueError("official_relay_not_found")
    signing_pub = str(found.get("signing_public_key_b64") or "").strip()
    if not signing_pub:
        raise PermissionError("official_relay_has_no_registered_signing_key")
    if not verify_signature(signing_pub, _heartbeat_signed_body(relay_id, ts), signature):
        raise PermissionError("invalid_heartbeat_signature")
    found["last_seen"] = now()
    found["status"] = "online"
    found["enabled"] = True
    save_payload(payload)
    return found


def upsert_contributor(item: dict) -> dict:
    relay_id, host, port, public_key, signing_public_key = _validate_registration(item)
    _verify_registration_signature(item)

    payload = load_clean_payload()
    relays = payload.setdefault("relays", [])

    # Anti-hijack: if this id already exists, the registering party must
    # control the previously registered signing key. If no signing key was
    # previously registered (legacy/pre-signing record), upsert is allowed
    # but the new signing key becomes the binding one going forward.
    existing = _find_contributor(payload, relay_id)
    if existing is not None:
        prior_signing_pub = str(existing.get("signing_public_key_b64") or "").strip()
        if prior_signing_pub and prior_signing_pub != signing_public_key:
            raise PermissionError("contributor_id_owned_by_different_signing_key")

    relay = {
        "id": relay_id,
        "role": "middle",
        "host": host,
        "port": port,
        "enabled": True,
        "official": False,
        "contributor": True,
        "status": "online",
        "last_seen": now(),
        "public_key_b64": public_key,
        "signing_public_key_b64": signing_public_key,
    }
    relays[:] = [r for r in relays if r.get("id") != relay_id]
    relays.append(relay)
    save_payload(payload)
    return relay


def heartbeat_contributor(item: dict) -> dict:
    relay_id = str(item.get("id") or "").strip()
    ts = int(item.get("ts") or 0)
    signature = str(item.get("signature_b64") or "").strip()
    if not _ID_RE.match(relay_id):
        raise ValueError("invalid_relay_id")
    if abs(time.time() - ts) > 60:
        raise ValueError("heartbeat_timestamp_out_of_window")
    payload = load_clean_payload()
    found = _find_contributor(payload, relay_id)
    if found is None:
        raise ValueError("contributor_not_found")
    signing_pub = str(found.get("signing_public_key_b64") or "").strip()
    if not signing_pub:
        # Legacy contributors without a registered signing key cannot heartbeat.
        raise PermissionError("contributor_has_no_registered_signing_key")
    if not verify_signature(signing_pub, _heartbeat_signed_body(relay_id, ts), signature):
        raise PermissionError("invalid_heartbeat_signature")
    found["last_seen"] = now()
    found["status"] = "online"
    found["enabled"] = True
    save_payload(payload)
    return found


def unregister_contributor(item: dict) -> bool:
    relay_id = str(item.get("id") or "").strip()
    ts = int(item.get("ts") or 0)
    signature = str(item.get("signature_b64") or "").strip()
    if not _ID_RE.match(relay_id):
        raise ValueError("invalid_relay_id")
    if abs(time.time() - ts) > 60:
        raise ValueError("unregister_timestamp_out_of_window")
    payload = load_payload()
    relays = payload.setdefault("relays", [])
    target = next((r for r in relays if r.get("id") == relay_id and r.get("contributor")), None)
    if target is None:
        return False
    signing_pub = str(target.get("signing_public_key_b64") or "").strip()
    if signing_pub:
        if not verify_signature(signing_pub, _unregister_signed_body(relay_id, ts), signature):
            raise PermissionError("invalid_unregister_signature")
    relays[:] = [r for r in relays if not (r.get("id") == relay_id and r.get("contributor"))]
    save_payload(payload)
    return True


# --- Signed /directory response ---------------------------------------------

def signed_directory_response() -> dict:
    """Return the directory payload wrapped with issued_at + signature.

    The body includes a fixed `kind` field for domain separation: an
    Ed25519 signature is just bytes, so without a `kind` discriminator a
    signature over a directory body could in principle be replayed onto
    any other endpoint that signs a similar shape. Adding `kind` ensures
    a directory signature can only ever validate for directory responses.
    """
    payload = load_clean_payload()
    body = {
        "kind": "directory",
        "relays": payload.get("relays", []),
        "issued_at": int(time.time()),
    }
    private = get_directory_signing_private_key()
    signature = private.sign(canonical_json(body))
    return {
        **body,
        "signature_b64": b64e(signature),
        "max_age_seconds": int(DIRECTORY_RESPONSE_MAX_AGE_SECONDS),
    }


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    try:
        method, path, body = await read_request(reader)
        if method == "OPTIONS":
            writer.write(http_json(200, {"ok": True}))
        elif method == "GET" and path in {"/", "/status"}:
            payload = load_clean_payload()
            contributors = [r for r in payload.get("relays", []) if r.get("contributor")]
            online = [r for r in contributors if r.get("enabled") and r.get("status") == "online"]
            writer.write(http_json(200, {"ok": True, "relays": len(payload.get("relays", [])), "contributors": len(contributors), "online_contributors": len(online)}))
        elif method == "GET" and path == "/directory":
            writer.write(http_json(200, signed_directory_response()))
        elif method == "GET" and path == "/signing-key":
            # TOFU bootstrap: lets a fresh client pin the directory's public
            # signing key on first use. Anyone on the network can read this;
            # that's by design — the public key is meant to be public. The
            # security relies on the client pinning it the first time and
            # detecting any later change.
            from shared.key_exchange import ensure_directory_signing_key
            data = ensure_directory_signing_key()
            writer.write(http_json(200, {
                "ok": True,
                "signing_public_key_b64": data["public_key_b64"],
                "advisory": "Pin this key. Subsequent /directory responses will be rejected if signed by a different key.",
            }))
        elif method == "POST" and path == "/register-relay":
            payload = json.loads(body.decode("utf-8") or "{}")
            try:
                relay = upsert_official_relay(payload)
            except PermissionError as exc:
                log_error("DIR", f"Official relay registration rejected from {peer}: {exc}")
                writer.write(http_json(403, {"ok": False, "error": str(exc)}))
                await writer.drain()
                return
            except ValueError as exc:
                log_error("DIR", f"Official relay registration validation failed from {peer}: {exc}")
                writer.write(http_json(400, {"ok": False, "error": str(exc)}))
                await writer.drain()
                return
            log_info("DIR", f"Registered official relay {relay['id']} at {relay['host']}:{relay['port']} from {peer}")
            writer.write(http_json(200, {"ok": True, "registered": True, "relay": relay}))
        elif method == "POST" and path == "/heartbeat-relay":
            payload = json.loads(body.decode("utf-8") or "{}")
            try:
                relay = heartbeat_official_relay(payload)
            except PermissionError as exc:
                log_error("DIR", f"Official relay heartbeat rejected from {peer}: {exc}")
                writer.write(http_json(403, {"ok": False, "error": str(exc)}))
                await writer.drain()
                return
            except ValueError as exc:
                writer.write(http_json(400, {"ok": False, "error": str(exc)}))
                await writer.drain()
                return
            writer.write(http_json(200, {"ok": True, "heartbeat": True, "relay": relay}))
        elif method == "POST" and path == "/register-contributor":
            payload = json.loads(body.decode("utf-8") or "{}")
            try:
                relay = upsert_contributor(payload)
            except PermissionError as exc:
                log_error("DIR", f"Registration rejected from {peer}: {exc}")
                writer.write(http_json(403, {"ok": False, "error": str(exc)}))
                await writer.drain()
                return
            except ValueError as exc:
                log_error("DIR", f"Registration validation failed from {peer}: {exc}")
                writer.write(http_json(400, {"ok": False, "error": str(exc)}))
                await writer.drain()
                return
            log_info("DIR", f"Registered contributor {relay['id']} at {relay['host']}:{relay['port']} from {peer}")
            writer.write(http_json(200, {"ok": True, "registered": True, "relay": relay}))
        elif method == "POST" and path == "/heartbeat-contributor":
            payload = json.loads(body.decode("utf-8") or "{}")
            try:
                relay = heartbeat_contributor(payload)
            except PermissionError as exc:
                log_error("DIR", f"Heartbeat rejected from {peer}: {exc}")
                writer.write(http_json(403, {"ok": False, "error": str(exc)}))
                await writer.drain()
                return
            except ValueError as exc:
                writer.write(http_json(400, {"ok": False, "error": str(exc)}))
                await writer.drain()
                return
            writer.write(http_json(200, {"ok": True, "heartbeat": True, "relay": relay}))
        elif method == "POST" and path == "/unregister-contributor":
            payload = json.loads(body.decode("utf-8") or "{}")
            try:
                changed = unregister_contributor(payload)
            except PermissionError as exc:
                log_error("DIR", f"Unregister rejected from {peer}: {exc}")
                writer.write(http_json(403, {"ok": False, "error": str(exc)}))
                await writer.drain()
                return
            except ValueError as exc:
                writer.write(http_json(400, {"ok": False, "error": str(exc)}))
                await writer.drain()
                return
            relay_id = str(payload.get("id") or "")
            log_info("DIR", f"Unregistered contributor {relay_id} changed={changed}")
            writer.write(http_json(200, {"ok": True, "unregistered": changed, "id": relay_id}))
        else:
            writer.write(http_json(404, {"ok": False, "error": "not_found"}))
        await writer.drain()
    except Exception as exc:
        log_error("DIR", f"Directory server error: {exc}")
        try:
            writer.write(http_json(400, {"ok": False, "error": "directory_error"}))
            await writer.drain()
        except Exception:
            pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def cleanup_loop() -> None:
    while True:
        await asyncio.sleep(15)
        try:
            load_clean_payload()
        except Exception as exc:
            log_error("DIR", f"Cleanup error: {exc}")


async def main() -> None:
    # The directory server is the source of truth for the relay topology.
    # If directory.json doesn't exist, complain loudly — this is the
    # operator's expected configuration file.
    if not DIRECTORY_PATH.exists():
        log_error(
            "DIR",
            f"directory.json not found at {DIRECTORY_PATH}. The directory server "
            f"requires this file as its database; copy the template (which lists "
            f"entry/middle/exit relays for your deployment) into the project root "
            f"before starting the server.",
        )
        # Initialize an empty payload so the server still starts but serves nothing.
        save_payload({"relays": []})
    # Generate or load the directory server's Ed25519 signing key. The public
    # key is written to directory_signing_pub.txt so it can be shipped to
    # clients via tools/install_client.py.
    #
    # Note: the directory server does NOT generate relay private keys. Each
    # relay machine generates its own keypair locally and registers its
    # public keys with this server via the signed /register-relay endpoint
    # at startup. This means even if the directory-server VPS is fully
    # compromised, the attacker does not gain the ability to decrypt any
    # onion layer destined for an official relay — they only see the
    # public-key registry, which they could already see by querying
    # /directory anyway.
    ensure_directory_signing_key()
    server = await asyncio.start_server(handle, DIRECTORY_SERVER_HOST, DIRECTORY_SERVER_PORT)
    log_info("DIR", f"Directory server listening on {DIRECTORY_SERVER_HOST}:{DIRECTORY_SERVER_PORT}")
    log_info("DIR", "Endpoints: GET /directory, GET /signing-key, POST /register-relay, POST /register-contributor, POST /heartbeat-relay, POST /heartbeat-contributor, POST /unregister-contributor")
    log_info("DIR", "Clients should run tools/install_client.py http://<this-server>:7071 to bake URL+pinned key into directory_config.json.")
    asyncio.create_task(cleanup_loop())
    async with server:
        await server.serve_forever()
