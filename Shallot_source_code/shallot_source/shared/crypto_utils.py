"""AES-GCM helpers for onion payload encryption plus optional fixed-size padding."""

from __future__ import annotations

import base64
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from shared.config import ONION_CELL_PLAINTEXT_SIZE

NONCE_SIZE = 12
PAD_MAGIC = b"OPAD1"


def json_to_bytes(data: dict) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def bytes_to_json(data: bytes) -> dict:
    return json.loads(data.decode("utf-8"))


def _pad_plaintext(plaintext: bytes, fixed_size: int) -> bytes:
    if fixed_size <= 0:
        return plaintext
    header_len = len(PAD_MAGIC) + 4
    if len(plaintext) + header_len > fixed_size:
        raise ValueError(
            f"Onion payload is too large for one padded cell: {len(plaintext)} bytes; "
            f"capacity is {fixed_size - header_len} bytes"
        )
    payload_len = len(plaintext).to_bytes(4, "big")
    padding_len = fixed_size - header_len - len(plaintext)
    return PAD_MAGIC + payload_len + plaintext + os.urandom(padding_len)


def _unpad_plaintext(data: bytes) -> bytes:
    if not data.startswith(PAD_MAGIC):
        return data
    header_len = len(PAD_MAGIC) + 4
    length = int.from_bytes(data[len(PAD_MAGIC):header_len], "big")
    return data[header_len:header_len + length]


def encrypt_json(key: bytes, payload: dict, *, padded: bool = False, fixed_size: int = ONION_CELL_PLAINTEXT_SIZE) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    plaintext = json_to_bytes(payload)
    if padded:
        plaintext = _pad_plaintext(plaintext, fixed_size)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_json(key: bytes, encrypted_b64: str) -> dict:
    raw = base64.b64decode(encrypted_b64.encode("ascii"))
    nonce = raw[:NONCE_SIZE]
    ciphertext = raw[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    plaintext = _unpad_plaintext(plaintext)
    return bytes_to_json(plaintext)
