"""Relay key management and X25519 session-key derivation.

Security model used by this project:

* Every relay owns its own X25519 private key.
* The directory contains only public relay information and public keys.
* Browsing clients use public keys from the directory to encrypt onion layers.
* Contributor users generate their own local private key and register only their
  public key with the directory server.
* A contributor VM/user must never receive the official network's
  relay_keys_dev.json file.

For local senior-project testing, the Windows machine may run all official
relays and therefore owns the private keys for those local official relays. A
contributor VM generates and stores only its own contributor private key.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

from shared.config import RELAY_KEYS_PATH

from shared.runtime_paths import runtime_root

PROJECT_ROOT = runtime_root()
DIRECTORY_PATH = PROJECT_ROOT / "directory.json"
KEYS_PATH = PROJECT_ROOT / RELAY_KEYS_PATH
DIRECTORY_SIGNING_KEY_PATH = PROJECT_ROOT / "directory_signing_key.json"
DIRECTORY_SIGNING_PUB_PATH = PROJECT_ROOT / "directory_signing_pub.txt"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _private_to_b64(private_key: x25519.X25519PrivateKey) -> str:
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return b64e(raw)


def _public_to_b64(public_key: x25519.X25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64e(raw)


def load_directory_payload() -> dict:
    with DIRECTORY_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    payload.setdefault("relays", [])
    return payload


def save_directory_payload(payload: dict) -> None:
    # Atomic write so a crash mid-write doesn't corrupt directory.json.
    DIRECTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = DIRECTORY_PATH.with_suffix(DIRECTORY_PATH.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    tmp.replace(DIRECTORY_PATH)


def _load_key_payload() -> dict:
    if KEYS_PATH.exists():
        with KEYS_PATH.open("r", encoding="utf-8") as handle:
            keys = json.load(handle)
    else:
        keys = {"relays": {}}
    keys.setdefault("relays", {})
    return keys


def _save_key_payload(keys: dict) -> None:
    # Atomic write so a crash mid-write doesn't corrupt the relay key file.
    KEYS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = KEYS_PATH.with_suffix(KEYS_PATH.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(keys, handle, indent=2)
        handle.write("\n")
    tmp.replace(KEYS_PATH)


def _new_key_record() -> dict:
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    signing_private = ed25519.Ed25519PrivateKey.generate()
    signing_public = signing_private.public_key()
    signing_priv_raw = signing_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    signing_pub_raw = signing_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "private_key_b64": _private_to_b64(private_key),
        "public_key_b64": _public_to_b64(public_key),
        "signing_private_key_b64": b64e(signing_priv_raw),
        "signing_public_key_b64": b64e(signing_pub_raw),
    }


def _ensure_signing_key_in_record(record: dict) -> bool:
    """Backfill an Ed25519 signing keypair into an older key record. Returns True if changed."""
    if "signing_private_key_b64" in record and "signing_public_key_b64" in record:
        return False
    signing_private = ed25519.Ed25519PrivateKey.generate()
    signing_public = signing_private.public_key()
    record["signing_private_key_b64"] = b64e(signing_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    record["signing_public_key_b64"] = b64e(signing_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))
    return True


def get_relay_signing_private_key(relay_id: str) -> ed25519.Ed25519PrivateKey:
    record = ensure_local_relay_key(relay_id, update_directory=True)
    keys = _load_key_payload()
    rec = keys["relays"][relay_id]
    if _ensure_signing_key_in_record(rec):
        _save_key_payload(keys)
        record = rec
    return ed25519.Ed25519PrivateKey.from_private_bytes(b64d(record["signing_private_key_b64"]))


def get_relay_signing_public_key_b64(relay_id: str) -> str:
    record = ensure_local_relay_key(relay_id, update_directory=True)
    keys = _load_key_payload()
    rec = keys["relays"][relay_id]
    if _ensure_signing_key_in_record(rec):
        _save_key_payload(keys)
        record = rec
    return record["signing_public_key_b64"]


def sign_with_relay_key(relay_id: str, message: bytes) -> str:
    """Return base64-encoded Ed25519 signature of `message` using relay_id's private signing key."""
    private = get_relay_signing_private_key(relay_id)
    return b64e(private.sign(message))


def verify_signature(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    """Verify an Ed25519 signature. Returns True iff valid."""
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(b64d(public_key_b64))
        pub.verify(b64d(signature_b64), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --- Directory-server signing key (used to sign /directory responses) ---------

def _write_local_directory_server_url() -> None:
    """When this machine IS the directory server, write directory_server_url.txt
    pointing at localhost. This file is the simplest, most-reliable way for any
    other process running from the same project root (proxy_client, relay
    servers) to discover the URL without an env var or directory_config.json.
    """
    try:
        from shared.config import DIRECTORY_SERVER_PORT
        url_file = PROJECT_ROOT / "directory_server_url.txt"
        target = f"http://127.0.0.1:{DIRECTORY_SERVER_PORT}\n"
        # Don't clobber an explicit override the operator may have written.
        if url_file.exists():
            existing = url_file.read_text(encoding="utf-8").strip()
            if existing and not existing.startswith("http://127.0.0.1:") and not existing.startswith("http://localhost:"):
                return
        url_file.write_text(target, encoding="utf-8")
    except Exception:
        pass


def ensure_directory_signing_key() -> dict:
    """Create or load the directory server's Ed25519 signing key.

    Run once on the directory-server machine. The public key is written to
    `directory_signing_pub.txt` so it can be shipped to clients (pinned).
    Also writes `directory_server_url.txt` with the localhost URL so other
    processes on this machine (proxy_client, official relays) can resolve
    the directory server without any extra configuration.
    """
    if DIRECTORY_SIGNING_KEY_PATH.exists():
        with DIRECTORY_SIGNING_KEY_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if "private_key_b64" in data and "public_key_b64" in data:
            DIRECTORY_SIGNING_PUB_PATH.write_text(data["public_key_b64"] + "\n", encoding="utf-8")
            _write_local_directory_server_url()
            return data

    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    data = {
        "private_key_b64": b64e(private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )),
        "public_key_b64": b64e(public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )),
    }
    DIRECTORY_SIGNING_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DIRECTORY_SIGNING_KEY_PATH.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    DIRECTORY_SIGNING_PUB_PATH.write_text(data["public_key_b64"] + "\n", encoding="utf-8")
    _write_local_directory_server_url()
    return data


def get_directory_signing_private_key() -> ed25519.Ed25519PrivateKey:
    data = ensure_directory_signing_key()
    return ed25519.Ed25519PrivateKey.from_private_bytes(b64d(data["private_key_b64"]))


DIRECTORY_CONFIG_PATH = PROJECT_ROOT / "directory_config.json"


def load_pinned_directory_signing_pub_key() -> str | None:
    """Client-side helper. Returns the pinned directory signing public key.

    Priority order:
      1. directory_config.json's "directory_signing_pub_key_b64" field
         (baked at install time — the canonical place)
      2. directory_signing_pub.txt (legacy/fallback, also written by the
         directory server itself when it generates its keypair)
      3. None (no pinned key — caller logs and accepts unsigned in dev mode)
    """
    try:
        if DIRECTORY_CONFIG_PATH.exists():
            with DIRECTORY_CONFIG_PATH.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                key = str(data.get("directory_signing_pub_key_b64") or "").strip()
                if key:
                    return key
    except Exception:
        pass
    if not DIRECTORY_SIGNING_PUB_PATH.exists():
        return None
    text = DIRECTORY_SIGNING_PUB_PATH.read_text(encoding="utf-8").strip()
    return text or None


def ensure_local_relay_key(relay_id: str, *, update_directory: bool = True, public_host: str | None = None) -> dict:
    """Ensure this machine owns a private key for exactly `relay_id`.

    Contributor machines call this only for their own contributor id. They do
    not receive or generate official relay private keys.

    If `public_host` is given, also update the relay's directory entry to
    advertise that host. This is for LAN-deployment exits/middles whose
    bind address (e.g. 0.0.0.0 or 127.0.0.1) is not what other machines
    must connect to. Only takes effect on the machine that owns the
    writable directory.json (the directory-server machine).
    """
    if not relay_id:
        raise ValueError("relay_id is required")
    keys = _load_key_payload()
    changed = False
    if relay_id not in keys["relays"]:
        keys["relays"][relay_id] = _new_key_record()
        changed = True
    else:
        # Backfill signing key for older records that pre-date the signing changes.
        if _ensure_signing_key_in_record(keys["relays"][relay_id]):
            changed = True
    if changed:
        _save_key_payload(keys)
    record = keys["relays"][relay_id]

    if update_directory and DIRECTORY_PATH.exists():
        payload = load_directory_payload()
        directory_changed = False
        for item in payload.get("relays", []):
            if item.get("id") == relay_id:
                if item.get("public_key_b64") != record["public_key_b64"]:
                    item["public_key_b64"] = record["public_key_b64"]
                    directory_changed = True
                if item.get("signing_public_key_b64") != record.get("signing_public_key_b64"):
                    item["signing_public_key_b64"] = record["signing_public_key_b64"]
                    directory_changed = True
                if public_host:
                    cleaned_host = public_host.strip()
                    if cleaned_host and item.get("host") != cleaned_host:
                        item["host"] = cleaned_host
                        directory_changed = True
                break
        if directory_changed:
            save_directory_payload(payload)
    return record


def ensure_official_relay_keys() -> dict:
    """Generate keys for all official relays in local directory.json.

    Use this only on the network-operator/development machine that runs the
    official relays and directory server. Do not run this on contributor-only
    machines.
    """
    payload = load_directory_payload()
    for item in payload.get("relays", []):
        is_contributor = bool(item.get("contributor", False))
        is_official = bool(item.get("official", not is_contributor))
        if is_official and not is_contributor:
            ensure_local_relay_key(str(item["id"]), update_directory=True)
    return _load_key_payload()


def load_or_create_local_relay_keys(*, include_all_official: bool = False) -> dict:
    """Compatibility wrapper used by existing relay runners.

    Default behavior creates only the local relay id from environment variables.
    include_all_official=True generates all official keys for the operator box
    (legacy single-machine setups; not used in the VPS deployment model).

    NOTE: this no longer mutates the local directory.json. Relays now publish
    their host and public keys to the directory server via the signed
    /register-relay HTTP endpoint at startup, the same way contributors
    register. The directory server's directory.json is the single source of
    truth, and it should only contain the operator-declared topology spec
    (id/role/port). Public keys and hosts are filled in dynamically from
    registrations.
    """
    if include_all_official:
        return ensure_official_relay_keys()

    local_ids = [
        os.getenv("RELAY_NAME"),
        os.getenv("SP_LOCAL_RELAY_ID"),
        os.getenv("SP_CONTRIBUTOR_RELAY_ID"),
    ]
    for relay_id in {item for item in local_ids if item}:
        ensure_local_relay_key(relay_id, update_directory=False)
    return _load_key_payload()


def get_relay_private_key(relay_id: str) -> x25519.X25519PrivateKey:
    record = ensure_local_relay_key(relay_id, update_directory=True)
    private_b64 = record["private_key_b64"]
    return x25519.X25519PrivateKey.from_private_bytes(b64d(private_b64))


def get_local_public_key_b64(relay_id: str) -> str:
    return ensure_local_relay_key(relay_id, update_directory=True)["public_key_b64"]


def public_key_from_b64(public_b64: str) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(b64d(public_b64))


def derive_layer_key(shared_secret: bytes, *, circuit_id: str, relay_id: str, role: str) -> bytes:
    info = f"senior-project-onion-layer|{circuit_id}|{relay_id}|{role}".encode("utf-8")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared_secret)


def client_make_kx(public_key_b64: str, *, circuit_id: str, relay_id: str, role: str) -> Tuple[dict, bytes]:
    if not public_key_b64:
        raise ValueError(f"Relay {relay_id} does not have a public_key_b64 in the directory")
    client_private = x25519.X25519PrivateKey.generate()
    client_public = client_private.public_key()
    relay_public = public_key_from_b64(public_key_b64)
    shared_secret = client_private.exchange(relay_public)
    key = derive_layer_key(shared_secret, circuit_id=circuit_id, relay_id=relay_id, role=role)
    kx = {
        "alg": "X25519-HKDF-SHA256",
        "client_pub_b64": _public_to_b64(client_public),
        "circuit_id": circuit_id,
        "relay_id": relay_id,
        "role": role,
    }
    return kx, key


def relay_derive_key(kx: dict, relay_id: str, role: str) -> bytes:
    if kx.get("alg") != "X25519-HKDF-SHA256":
        raise ValueError("Unsupported key exchange algorithm")
    if kx.get("relay_id") != relay_id:
        raise ValueError(f"Key exchange is for relay {kx.get('relay_id')}, not {relay_id}")
    if kx.get("role") != role:
        raise ValueError(f"Key exchange role mismatch: {kx.get('role')} != {role}")
    private_key = get_relay_private_key(relay_id)
    client_public = x25519.X25519PublicKey.from_public_bytes(b64d(kx["client_pub_b64"]))
    shared_secret = private_key.exchange(client_public)
    return derive_layer_key(shared_secret, circuit_id=kx["circuit_id"], relay_id=relay_id, role=role)
