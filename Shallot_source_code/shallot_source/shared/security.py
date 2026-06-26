"""Security hardening helpers shared by client and relays."""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
import urllib.request
from pathlib import Path

from shared.config import (
    CONTROL_TOKEN_PATH,
    CONTROL_TOKEN_JS_PATH,
    REPLAY_NONCE_CACHE_SECONDS,
    REPLAY_WINDOW_SECONDS,
    DIRECTORY_CACHE_TTL_SECONDS,
    DIRECTORY_RESPONSE_MAX_AGE_SECONDS,
    DIRECTORY_FETCH_TIMEOUT_SECONDS,
)
from shared.key_exchange import verify_signature, load_pinned_directory_signing_pub_key
from shared.logging_utils import log_error, log_info
from shared.runtime_paths import runtime_root

PROJECT_ROOT = runtime_root()
DIRECTORY_PATH = PROJECT_ROOT / "directory.json"
DIRECTORY_SERVER_URL_PATH = PROJECT_ROOT / "directory_server_url.txt"
# Single-file install config that ships with the client, baked at install
# time. Contains the directory server URL and the pinned signing public key.
# Replaces the older split between directory_server_url.txt and
# directory_signing_pub.txt (both still readable for backwards compat).
DIRECTORY_CONFIG_PATH = PROJECT_ROOT / "directory_config.json"
CONTROL_TOKEN_FILE = PROJECT_ROOT / CONTROL_TOKEN_PATH
CONTROL_TOKEN_JS_FILE = PROJECT_ROOT / CONTROL_TOKEN_JS_PATH
_SEEN_REPLAY_NONCES: dict[str, dict[str, float]] = {}


def _load_directory_config() -> dict:
    """Read directory_config.json, the canonical baked-in client config.

    Returns an empty dict if the file doesn't exist (e.g. on the directory
    server machine, or on a fresh checkout that hasn't been installed yet).
    """
    try:
        if DIRECTORY_CONFIG_PATH.exists():
            with DIRECTORY_CONFIG_PATH.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def get_directory_server_url() -> str:
    """Resolve the directory server URL.

    Priority order:
      1. Environment variable SP_DIRECTORY_SERVER_URL (operator override)
      2. directory_config.json's "directory_server_url" field (baked at install)
      3. Legacy directory_server_url.txt (backwards compat)
      4. Auto-detect: if this machine has the directory server's private
         signing key (directory_signing_key.json), it IS the directory
         server, so we can reach it at http://localhost:<port>. This lets
         the proxy_client + relay processes on the directory-server
         machine fetch the live directory without any extra config.
      5. Empty string

    The intended deployment model is that the URL is baked into
    directory_config.json at client install time, so end users never have
    to know or type the URL. The auto-detect path covers the case where
    the directory server and the client run from the same project root
    (single-machine demo / dev setup).
    """
    env = os.getenv("SP_DIRECTORY_SERVER_URL", "").strip().rstrip("/")
    if env:
        return env
    cfg = _load_directory_config()
    cfg_url = str(cfg.get("directory_server_url") or "").strip().rstrip("/")
    if cfg_url:
        return cfg_url
    try:
        if DIRECTORY_SERVER_URL_PATH.exists():
            file_url = DIRECTORY_SERVER_URL_PATH.read_text(encoding="utf-8").strip().rstrip("/")
            if file_url:
                return file_url
    except Exception:
        pass
    # Auto-detect: directory_signing_key.json (the PRIVATE half) only
    # exists on the directory-server machine. If we see it, we know the
    # directory server is local and we can reach it at localhost.
    try:
        from pathlib import Path as _P
        ds_key = PROJECT_ROOT / "directory_signing_key.json"
        if ds_key.exists():
            from shared.config import DIRECTORY_SERVER_PORT
            return f"http://127.0.0.1:{DIRECTORY_SERVER_PORT}"
    except Exception:
        pass
    return ""


def set_directory_server_url(url: str) -> None:
    """Persist the directory server URL to disk so it survives restarts.

    Called by the control API when an operator changes the URL via the
    Settings popup. Also sets the process env var so the change takes
    effect immediately for the running refresher thread.

    For end-user installs this is normally not called — the URL lives
    in directory_config.json and is baked at install time. This setter
    is reserved for operator workflows (e.g. moving the directory server
    to a new VPS).
    """
    cleaned = (url or "").strip().rstrip("/")
    if cleaned:
        _atomic_write(DIRECTORY_SERVER_URL_PATH, cleaned + "\n")
        os.environ["SP_DIRECTORY_SERVER_URL"] = cleaned
    else:
        try:
            DIRECTORY_SERVER_URL_PATH.unlink()
        except FileNotFoundError:
            pass
        os.environ.pop("SP_DIRECTORY_SERVER_URL", None)


def get_or_create_control_token() -> str:
    token = ""
    if CONTROL_TOKEN_FILE.exists():
        token = CONTROL_TOKEN_FILE.read_text(encoding="utf-8").strip()
    if len(token) < 32:
        token = secrets.token_urlsafe(32)
        _atomic_write(CONTROL_TOKEN_FILE, token + "\n")
    js = (
        "// Auto-generated by the local onion client. Do not commit real tokens.\n"
        f"window.ONION_CONTROL_TOKEN = {json.dumps(token)};\n"
        f"window.CONTROL_API_TOKEN = {json.dumps(token)};\n"
    )
    try:
        _atomic_write(CONTROL_TOKEN_JS_FILE, js)
    except Exception:
        pass
    return token


# --- Directory cache + signature verification --------------------------------
#
# The directory must be consulted by both validate_next_hop (per onion-packet,
# on relays) and circuit selection (on the client). Re-fetching it from the
# directory server every time would add an HTTP round-trip per packet and stall
# on every directory-server hiccup. Instead we cache the parsed directory in
# memory.
#
# Critically, callers (validate_next_hop, choose_circuit) run on asyncio event
# loops and must NEVER block on a network fetch. So the cache always returns
# its current contents synchronously, and a dedicated *background thread*
# refreshes the cache every DIRECTORY_CACHE_TTL_SECONDS. The first access
# performs a synchronous local-file load (no network), and the background
# refresher takes over from there.

_DIR_CACHE_LOCK = threading.Lock()
_DIR_CACHE_PAYLOAD: dict | None = None
_DIR_CACHE_FETCHED_AT: float = 0.0
_DIR_CACHE_SOURCE: str = "uninitialized"
_DIR_CACHE_LAST_ERROR: str | None = None
_DIR_CACHE_REFRESHER: threading.Thread | None = None
_DIR_CACHE_REFRESHER_STOP = threading.Event()


def _canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _verify_signed_directory(payload: dict) -> bool:
    """Returns True iff the payload has a valid signature from the pinned key
    AND was issued recently. If no pinned key is installed (legacy mode), we
    accept the payload but log loudly. This degraded mode is intended for
    initial bootstrap; a real deployment should always pin the key."""
    global _DIR_CACHE_LAST_ERROR
    pinned = load_pinned_directory_signing_pub_key()
    signature = str(payload.get("signature_b64") or "").strip()
    issued_at = int(payload.get("issued_at") or 0)
    max_age = int(payload.get("max_age_seconds") or DIRECTORY_RESPONSE_MAX_AGE_SECONDS)

    if not pinned:
        log_error("DIR-CLIENT", "No pinned directory signing key found; accepting unsigned directory (DEVELOPMENT ONLY). Run tools/pin_directory_key.py to pin the key.")
        _DIR_CACHE_LAST_ERROR = "no_pinned_key_dev_mode"
        return True

    if not signature or not issued_at:
        log_error("DIR-CLIENT", "Directory response is missing signature/issued_at; rejecting")
        _DIR_CACHE_LAST_ERROR = "response_missing_signature"
        return False

    if abs(time.time() - issued_at) > max_age:
        log_error("DIR-CLIENT", f"Directory response is stale (issued_at={issued_at}); rejecting")
        _DIR_CACHE_LAST_ERROR = "response_stale"
        return False

    # Body bytes that the server signed. Newer servers include a fixed
    # `kind: "directory"` field for cross-endpoint domain separation. We
    # try the new shape first and fall back to the legacy shape for
    # one release so that a client built from this codebase still works
    # against a directory server that hasn't been redeployed yet. After
    # both sides have been upgraded, the legacy fallback can be removed.
    body_with_kind = {
        "kind": "directory",
        "relays": payload.get("relays", []),
        "issued_at": issued_at,
    }
    body_legacy = {
        "relays": payload.get("relays", []),
        "issued_at": issued_at,
    }
    if (verify_signature(pinned, _canonical_json(body_with_kind), signature)
            or verify_signature(pinned, _canonical_json(body_legacy), signature)):
        return True
    log_error(
        "DIR-CLIENT",
        "Directory signature verification FAILED; the pinned signing key on this machine "
        "does not match the directory server's current key. Run tools/pin_directory_key.py "
        "<URL> to re-pin, then restart proxy_client.",
    )
    _DIR_CACHE_LAST_ERROR = "signature_mismatch_check_pinned_key"
    return False


# Build a urllib opener that bypasses the system HTTP proxy. Without this,
# on Windows where the user has set the system proxy to 127.0.0.1:8080
# (the local onion proxy itself), urllib.request.urlopen would route the
# directory fetch THROUGH the local onion proxy — which would fail with
# 503 because no circuit exists yet, creating a chicken-and-egg deadlock.
# The directory fetch must always go direct.
_DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _fetch_remote_directory_payload() -> dict | None:
    """Blocking HTTP fetch. ONLY call from the background refresher thread."""
    global _DIR_CACHE_LAST_ERROR
    url = get_directory_server_url()
    if not url:
        _DIR_CACHE_LAST_ERROR = "no_directory_server_url_configured"
        return None
    try:
        with _DIRECT_OPENER.open(url + "/directory", timeout=DIRECTORY_FETCH_TIMEOUT_SECONDS) as response:
            data = json.loads(response.read().decode("utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("relays"), list):
            _DIR_CACHE_LAST_ERROR = "remote_payload_malformed"
            return None
        if not _verify_signed_directory(data):
            # _verify_signed_directory already set a more specific error.
            return None
        _DIR_CACHE_LAST_ERROR = None
        return data
    except Exception as exc:
        _DIR_CACHE_LAST_ERROR = f"fetch_failed: {exc}"
        return None


def _load_local_directory_payload() -> dict:
    """Load the bundled local directory.json IF IT EXISTS.

    In the new install model, end-user clients DO NOT ship a local
    directory.json; the relay topology is fetched live from the directory
    server. Only the directory-server machine itself should have this
    file. So missing-file is a normal, expected state on clients — we
    return an empty payload instead of raising. The cache will then
    behave as if the directory has no relays, and any browsing attempt
    will surface a clear "directory unreachable" error until the
    background refresher gets a real response from the directory server.

    If the file IS present (legacy install or the directory server
    itself), we still strip any `contributor: true` entries as a defense
    in depth, since a contributor's authority must come from a live
    signed registration, never from a bundled file.
    """
    if not DIRECTORY_PATH.exists():
        return {"relays": [], "_local_source": "missing"}
    with DIRECTORY_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    relays = payload.get("relays", [])
    filtered = [r for r in relays if not r.get("contributor")]
    dropped = len(relays) - len(filtered)
    if dropped > 0:
        log_error(
            "DIR-CLIENT",
            f"Bundled directory.json contained {dropped} contributor entry(ies). "
            f"Contributors must only come from the live directory server; the bundled "
            f"entries have been ignored. Please remove them from the shipped file.",
        )
    payload["relays"] = filtered
    return payload


def _store_payload(payload: dict, source: str) -> None:
    global _DIR_CACHE_PAYLOAD, _DIR_CACHE_FETCHED_AT, _DIR_CACHE_SOURCE
    with _DIR_CACHE_LOCK:
        _DIR_CACHE_PAYLOAD = payload
        _DIR_CACHE_FETCHED_AT = time.time()
        _DIR_CACHE_SOURCE = source


def _ensure_initial_cache() -> None:
    """Synchronous, non-blocking cache initialization on first access.

    Loads from the local directory.json (no network) so the first lookup
    returns immediately. The background refresher then takes over.
    """
    if _DIR_CACHE_PAYLOAD is not None:
        return
    try:
        local = _load_local_directory_payload()
        _store_payload(local, "local_file")
    except Exception as exc:
        # Even local-file load failed; surface a clear error to the caller.
        raise RuntimeError(f"Could not load any directory: {exc}")


_DIR_CACHE_REFRESH_NOW = threading.Event()


def _refresher_loop() -> None:
    """Background thread that refreshes the cache from the directory server.

    Runs out-of-band so asyncio handlers never block on a network fetch.
    Logs prominently when the cache transitions between sources so the user
    can spot a fallback to stale local data quickly.
    """
    last_logged_source: str | None = None
    last_logged_error: str | None = None
    while not _DIR_CACHE_REFRESHER_STOP.is_set():
        try:
            remote = _fetch_remote_directory_payload()
            if remote is not None:
                _store_payload(remote, "directory_server")
        except Exception as exc:
            global _DIR_CACHE_LAST_ERROR
            _DIR_CACHE_LAST_ERROR = f"refresher_error: {exc}"

        # Surface transitions: source changes or new error reasons.
        with _DIR_CACHE_LOCK:
            current_source = _DIR_CACHE_SOURCE
            current_error = _DIR_CACHE_LAST_ERROR
        if current_source != last_logged_source:
            if current_source == "directory_server":
                log_info(
                    "DIR-CLIENT",
                    "Directory cache is now served from the live directory server.",
                )
            elif current_source == "local_file":
                log_error(
                    "DIR-CLIENT",
                    f"Directory cache is using the bundled local directory.json. "
                    f"Live server fetch state: {current_error or 'unknown'}. "
                    f"Contributors will be invisible until the live server is reachable and signature verification passes.",
                )
            last_logged_source = current_source
        elif current_error and current_error != last_logged_error and current_source == "local_file":
            log_error(
                "DIR-CLIENT",
                f"Directory refresh still failing: {current_error}. Cache stays on bundled local file.",
            )
            last_logged_error = current_error

        # Wait either for the TTL OR for an explicit refresh-now signal.
        triggered = _DIR_CACHE_REFRESH_NOW.wait(timeout=DIRECTORY_CACHE_TTL_SECONDS)
        _DIR_CACHE_REFRESH_NOW.clear()
        if _DIR_CACHE_REFRESHER_STOP.is_set():
            return


def request_directory_refresh() -> None:
    """Wake the background refresher thread.

    Safe to call from asyncio coroutines; does not block the event loop.
    """
    _DIR_CACHE_REFRESH_NOW.set()


def start_directory_refresher() -> None:
    """Start the background refresh thread if it isn't already running.

    Idempotent. Safe to call from any process that uses the directory.
    """
    global _DIR_CACHE_REFRESHER
    if _DIR_CACHE_REFRESHER is not None and _DIR_CACHE_REFRESHER.is_alive():
        return
    _DIR_CACHE_REFRESHER_STOP.clear()
    _DIR_CACHE_REFRESH_NOW.clear()
    _DIR_CACHE_REFRESHER = threading.Thread(target=_refresher_loop, name="directory-refresher", daemon=True)
    _DIR_CACHE_REFRESHER.start()


def stop_directory_refresher() -> None:
    _DIR_CACHE_REFRESHER_STOP.set()
    _DIR_CACHE_REFRESH_NOW.set()  # wake the thread so it can exit


def load_directory_payload(*, force_refresh: bool = False) -> dict:
    """Synchronous, non-blocking cache reader.

    Always returns immediately. Never makes a network call from this function.
    The first call loads from local directory.json; subsequent calls return
    whatever the background refresher has cached.

    `force_refresh=True` from a synchronous (non-asyncio) context performs an
    immediate blocking fetch. From an asyncio context, prefer
    `request_directory_refresh()` which only signals the refresher thread.
    """
    if force_refresh:
        remote = _fetch_remote_directory_payload()
        if remote is not None:
            _store_payload(remote, "directory_server")
            return remote
        # If forced fetch failed, fall through to whatever's cached.

    if _DIR_CACHE_PAYLOAD is None:
        _ensure_initial_cache()

    with _DIR_CACHE_LOCK:
        # Defensive copy of the top-level dict so callers can't mutate the cache.
        return dict(_DIR_CACHE_PAYLOAD) if _DIR_CACHE_PAYLOAD is not None else {"relays": []}


def directory_cache_status() -> dict:
    with _DIR_CACHE_LOCK:
        return {
            "fetched_at": _DIR_CACHE_FETCHED_AT,
            "age_seconds": time.time() - _DIR_CACHE_FETCHED_AT if _DIR_CACHE_FETCHED_AT else None,
            "source": _DIR_CACHE_SOURCE,
            "last_error": _DIR_CACHE_LAST_ERROR,
            "ttl_seconds": DIRECTORY_CACHE_TTL_SECONDS,
            "have_pinned_signing_key": bool(load_pinned_directory_signing_pub_key()),
            "refresher_running": _DIR_CACHE_REFRESHER is not None and _DIR_CACHE_REFRESHER.is_alive(),
        }


def allowed_next_hops_for_role(role: str) -> set[tuple[str, int]]:
    """Return directory-approved next hops for a relay role.

    Entry may forward only to middle-role relays. Middle may forward to another
    middle-role relay (contributor path) or to an exit relay.
    """
    next_roles = {"entry": {"middle"}, "middle": {"middle", "exit"}}.get(role)
    if not next_roles:
        return set()
    payload = load_directory_payload()
    allowed: set[tuple[str, int]] = set()
    for item in payload.get("relays", []):
        status = str(item.get("status", "online"))
        if item.get("enabled", True) and status != "offline" and item.get("role") in next_roles:
            allowed.add((str(item["host"]), int(item["port"])))
    return allowed


def validate_next_hop(role: str, host: str, port: int) -> None:
    if role not in {"entry", "middle"}:
        return
    allowed = allowed_next_hops_for_role(role)
    if (host, int(port)) not in allowed:
        raise PermissionError("next_hop_not_whitelisted")


def add_replay_fields(payload: dict) -> dict:
    hardened = dict(payload)
    hardened["replay_ts"] = int(time.time())
    hardened["replay_nonce"] = secrets.token_urlsafe(18)
    return hardened


def validate_replay_fields(relay_id: str, payload: dict) -> None:
    now = time.time()
    ts = payload.get("replay_ts")
    nonce = payload.get("replay_nonce")
    if not isinstance(ts, int):
        raise ValueError("missing_or_invalid_replay_timestamp")
    if abs(now - ts) > REPLAY_WINDOW_SECONDS:
        raise ValueError("replay_window_expired")
    if not isinstance(nonce, str) or len(nonce) < 16:
        raise ValueError("missing_or_invalid_replay_nonce")
    cache = _SEEN_REPLAY_NONCES.setdefault(relay_id, {})
    cutoff = now - REPLAY_NONCE_CACHE_SECONDS
    for seen_nonce, seen_at in list(cache.items()):
        if seen_at < cutoff:
            cache.pop(seen_nonce, None)
    if nonce in cache:
        raise ValueError("replayed_onion_layer")
    cache[nonce] = now
