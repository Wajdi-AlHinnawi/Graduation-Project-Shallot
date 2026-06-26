import asyncio
import ipaddress
import time
from collections import deque
from typing import Deque, Dict

from shared.config import (
    RELAY_MAX_CONCURRENT_CONNECTIONS,
    RELAY_PER_IP_MAX_CONNECTIONS_PER_WINDOW,
    RELAY_PER_IP_RATE_LIMIT_WINDOW_SECONDS,
)
from shared.crypto_utils import decrypt_json, encrypt_json
from shared.key_exchange import relay_derive_key
from shared.logging_utils import log_error, log_info, log_debug
from shared.protocol import round_trip_json
from shared.security import validate_next_hop, validate_replay_fields, load_directory_payload


# --- Flaw 17: connection caps -------------------------------------------------

class RelayConnectionLimiter:
    """Per-relay-process semaphore + per-IP sliding-window rate limit.

    Localhost mode creates many short-lived framed JSON TCP connections. The
    browser also opens bursts of CONNECT tunnels. Therefore loopback peers are
    exempt from the per-IP limiter and are controlled by the semaphore only.

    LAN-deployment note: when relays run on different machines (or all bind
    to the same LAN IP rather than 127.0.0.1), the previous-hop relay's
    connections to this relay come from a non-loopback IP. Each CONNECT
    tunnel poll/data exchange is a separate TCP connection, so a single
    heavy browsing session can easily generate thousands of connections
    from the same source IP within the rate-limit window. To prevent the
    rate limiter from choking legitimate relay-to-relay traffic, peers
    whose IP appears in the (signed) directory as an enabled relay are
    also exempt from the per-IP limit. The semaphore still bounds the
    total concurrent work the relay will accept.
    """

    def __init__(self) -> None:
        self.semaphore = asyncio.Semaphore(RELAY_MAX_CONCURRENT_CONNECTIONS)
        self._per_ip_history: Dict[str, Deque[float]] = {}
        # Cache of directory-listed relay IPs. Refreshed lazily; the cache key
        # is the directory's id() so we automatically invalidate when the
        # background refresher swaps in a new payload.
        self._relay_ip_cache_key: int = 0
        self._relay_ip_cache: set[str] = set()

    def _peer_ip(self, peer) -> str:
        if isinstance(peer, tuple) and peer:
            return str(peer[0])
        return str(peer) if peer is not None else "unknown"

    def _is_loopback_peer(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_loopback
        except ValueError:
            return ip in {"localhost", "::1"}

    def _is_directory_listed_relay_peer(self, ip: str) -> bool:
        """Return True if `ip` belongs to an enabled relay in the signed directory.

        This is what makes legitimate same-LAN relay-to-relay traffic exempt
        from the per-IP rate limit. We rely on the directory cache, which is
        constant-time and refreshed in the background, so this stays fast on
        the per-connection hot path.
        """
        try:
            payload = load_directory_payload()
        except Exception:
            return False
        # Re-extract IPs only when the cached dict object changes.
        cache_key = id(payload)
        if cache_key != self._relay_ip_cache_key:
            ips: set[str] = set()
            for relay in payload.get("relays", []):
                if not relay.get("enabled", True):
                    continue
                if relay.get("status") == "offline":
                    continue
                host = str(relay.get("host") or "").strip()
                if not host:
                    continue
                # Only include actual IP addresses; hostnames would require
                # DNS resolution, which is too expensive for the hot path.
                try:
                    ipaddress.ip_address(host)
                    ips.add(host)
                except ValueError:
                    pass
            self._relay_ip_cache = ips
            self._relay_ip_cache_key = cache_key
        return ip in self._relay_ip_cache

    def check_rate_limit(self, peer) -> bool:
        """Return True if this connection from `peer` may proceed."""
        ip = self._peer_ip(peer)

        # Do not rate-limit local development traffic. If loopback is rejected,
        # the client sees: "0 bytes read on a total of 4 expected bytes".
        if self._is_loopback_peer(ip):
            return True

        # Do not rate-limit peers that are themselves relays in the signed
        # directory. A single heavy browsing session can open thousands of
        # short-lived TCP connections between adjacent relays (every CONNECT
        # tunnel poll is a separate connection) and that is legitimate
        # traffic, not a flooding attempt.
        if self._is_directory_listed_relay_peer(ip):
            return True

        now = time.time()
        cutoff = now - RELAY_PER_IP_RATE_LIMIT_WINDOW_SECONDS
        history = self._per_ip_history.setdefault(ip, deque())
        while history and history[0] < cutoff:
            history.popleft()
        if len(history) >= RELAY_PER_IP_MAX_CONNECTIONS_PER_WINDOW:
            return False
        history.append(now)
        if len(self._per_ip_history) > 10000:
            stale = [k for k, v in self._per_ip_history.items() if not v or v[-1] < cutoff]
            for k in stale:
                self._per_ip_history.pop(k, None)
        return True


def make_connection_limiter() -> RelayConnectionLimiter:
    return RelayConnectionLimiter()


# --- Onion layer helpers ------------------------------------------------------

def decrypt_relay_layer(message: dict, relay_id: str, role: str) -> dict:
    kx = message.get("kx")
    if not kx:
        raise ValueError("Missing key-exchange envelope (kx)")
    key = relay_derive_key(kx, relay_id, role)
    return decrypt_json(key, message["layer_b64"])


def decrypt_relay_layer_with_key(message: dict, relay_id: str, role: str) -> tuple[dict, bytes]:
    """Like decrypt_relay_layer but also returns the derived AES-GCM key.

    The key is needed to encrypt the response before returning it upstream,
    so that responses are protected with the same layered encryption as requests.
    """
    kx = message.get("kx")
    if not kx:
        raise ValueError("Missing key-exchange envelope (kx)")
    key = relay_derive_key(kx, relay_id, role)
    return decrypt_json(key, message["layer_b64"]), key


def _extract_next_layer(inner: dict):
    if "payload" in inner:
        return inner["payload"]
    legacy_inner_message = inner.get("inner_message")
    if isinstance(legacy_inner_message, dict) and "layer_b64" in legacy_inner_message:
        return legacy_inner_message["layer_b64"]
    raise KeyError("payload")


async def relay_packet(message: dict, relay_name: str, relay_id: str, role: str, *, inner: dict | None = None, relay_key: bytes | None = None):
    """Forward an onion packet one hop further along the circuit.

    The optional `inner` parameter accepts an already-decrypted layer dict,
    allowing the calling relay handler to decrypt once (e.g. to extract
    session_id for logging) and reuse the result here instead of paying the
    cost of a second AES-GCM decrypt + JSON parse per packet.

    The optional `relay_key` parameter provides the pre-derived AES-GCM key
    when `inner` was obtained externally via decrypt_relay_layer_with_key().
    """
    quiet = bool(message.get("quiet", False))
    padding = message.get("padding") if isinstance(message.get("padding"), dict) else None
    if inner is None:
        inner, relay_key = decrypt_relay_layer_with_key(message, relay_id, role)
    elif relay_key is None:
        # Fallback: re-derive if inner was passed without the key
        kx = message.get("kx")
        if kx:
            relay_key = relay_derive_key(kx, relay_id, role)
    validate_replay_fields(relay_id, inner)
    session = inner.get("session_id")

    if not quiet:
        pad_note = " | padding=ON" if padding and padding.get("enabled") else ""
        log_info(relay_name, f"Layer decrypted successfully{pad_note}", session=session)

    next_host = inner["next_host"]
    next_port = int(inner["next_port"])
    validate_next_hop(role, next_host, next_port)
    next_layer_b64 = _extract_next_layer(inner)
    next_message = {"type": "onion", "layer_b64": next_layer_b64, "kx": inner["next_kx"], "quiet": quiet}
    if padding and padding.get("enabled"):
        next_message["padding"] = padding

    inner_summary = inner.get("action") or inner.get("type") or "packet"
    if not quiet:
        log_info(relay_name, f"Forwarding {inner_summary} to next hop {next_host}:{next_port} ({len(next_layer_b64)} chars of ciphertext)", session=session)

    response = await round_trip_json(next_host, next_port, next_message, verbose=not quiet)
    if not response.get("ok"):
        if not quiet:
            log_error(relay_name, f"Next hop returned error: {response.get('code', 'relay_error')}", session=session)
    elif not quiet:
        log_info(relay_name, "Next hop returned success", session=session)

    # Wrap the response in an encryption layer so the upstream hop
    # (or the client) must hold this relay's session key to read it.
    if relay_key is not None:
        encrypted_response_b64 = encrypt_json(relay_key, response)
        response = {"ok": True, "encrypted_response_b64": encrypted_response_b64}
        if not quiet:
            log_info(relay_name, f"Response encrypted for upstream ({len(encrypted_response_b64)} chars of ciphertext)", session=session)

    return response
