"""shared/protocol.py

Shared framing and transport helpers for the client and relays.

Normal mode sends compact length-prefixed JSON messages. Optional high-privacy
mode pads each relay-to-relay JSON frame to the same byte length so an observer
cannot distinguish Client->Entry, Entry->Middle, Middle->Exit, or reverse-path
messages by size.
"""

import asyncio
import base64
import contextlib
import json
import os
import struct
from typing import Dict, Any
from shared.logging_utils import log_debug
from shared.config import MAX_RELAY_FRAME_SIZE

HEADER_STRUCT = struct.Struct("!I")
CELL_PADDING_FIELD = "_cell_padding_b64"


def _json_bytes(message: Dict[str, Any]) -> bytes:
    return json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _with_fixed_json_size(message: Dict[str, Any], fixed_size: int | None) -> bytes:
    """Return compact JSON bytes, optionally padded to exactly fixed_size bytes.

    Padding is a random base64 string in a reserved field. It is transport
    padding, not an onion command. Receivers remove it before processing.
    """
    clean = dict(message)
    clean.pop(CELL_PADDING_FIELD, None)
    if not fixed_size:
        return _json_bytes(clean)

    fixed_size = int(fixed_size)
    if fixed_size <= 0:
        return _json_bytes(clean)

    candidate = dict(clean)
    candidate[CELL_PADDING_FIELD] = ""
    base_len = len(_json_bytes(candidate))
    if base_len > fixed_size:
        raise ValueError(f"Padded onion cell too small: message is {base_len} bytes, cell size is {fixed_size} bytes")

    # Base64 is ASCII. Generate random bytes, then trim the encoded string so the
    # final JSON body is exactly fixed_size bytes. If the required pad length is
    # not a valid base64 multiple, this is fine because the receiver never decodes
    # the padding; it only removes the field.
    needed = fixed_size - base_len
    if needed:
        candidate[CELL_PADDING_FIELD] = base64.b64encode(os.urandom(max(1, needed))).decode("ascii")[:needed]
    data = _json_bytes(candidate)

    # JSON escaping should make the calculation exact, but adjust defensively.
    if len(data) < fixed_size:
        candidate[CELL_PADDING_FIELD] += "A" * (fixed_size - len(data))
        data = _json_bytes(candidate)
    if len(data) > fixed_size:
        over = len(data) - fixed_size
        candidate[CELL_PADDING_FIELD] = candidate[CELL_PADDING_FIELD][:-over]
        data = _json_bytes(candidate)
    if len(data) != fixed_size:
        raise ValueError(f"Could not build exact padded onion cell: got {len(data)} bytes, wanted {fixed_size}")
    return data


async def send_json(writer, message: Dict[str, Any], *, padded_cell_size: int | None = None) -> None:
    """Send one JSON message with a 4-byte length prefix.

    If padded_cell_size is set, the JSON body length is exactly that size.
    """
    data = _with_fixed_json_size(message, padded_cell_size)
    writer.write(HEADER_STRUCT.pack(len(data)))
    writer.write(data)
    await writer.drain()


async def recv_json(reader) -> Dict[str, Any]:
    """Receive one length-prefixed JSON message."""
    header = await reader.readexactly(HEADER_STRUCT.size)
    (length,) = HEADER_STRUCT.unpack(header)
    if length < 0 or length > MAX_RELAY_FRAME_SIZE:
        raise ValueError("relay_frame_too_large")
    payload = await reader.readexactly(length)
    message = json.loads(payload.decode("utf-8"))
    if isinstance(message, dict):
        message.pop(CELL_PADDING_FIELD, None)
    return message


def b64_encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_decode_bytes(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def padding_cell_size_from_message(message: Dict[str, Any]) -> int | None:
    padding = message.get("padding") if isinstance(message, dict) else None
    if not isinstance(padding, dict) or not padding.get("enabled"):
        return None
    try:
        return int(padding.get("cell_size") or 0) or None
    except Exception:
        return None


async def safe_close_writer(writer, tag: str, verbose: bool = True) -> None:
    """Close a writer defensively without noisy shutdown failures."""
    if writer is None:
        return

    transport = None
    try:
        transport = writer.transport
    except Exception:
        transport = None

    try:
        writer.close()
    except Exception as exc:
        if verbose:
            log_debug(tag, f"Writer close warning: {exc}")

    try:
        await writer.wait_closed()
        return
    except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, RuntimeError) as exc:
        if verbose:
            log_debug(tag, f"Writer close warning: {exc}")
    except asyncio.CancelledError:
        if transport is not None:
            with contextlib.suppress(Exception):
                transport.abort()
        raise
    except Exception as exc:
        if verbose:
            log_debug(tag, f"Writer close warning: {exc}")

    if transport is not None:
        with contextlib.suppress(Exception):
            transport.abort()


async def round_trip_json(host: str, port: int, message: Dict[str, Any], verbose: bool = True) -> Dict[str, Any]:
    """Open TCP connection, send one JSON message, receive one JSON response."""
    cell_size = padding_cell_size_from_message(message)
    if verbose:
        mode = f" padded={cell_size}" if cell_size else ""
        log_debug("PROTO", f"Opening JSON round-trip connection to {host}:{port}{mode}")
    reader, writer = await asyncio.open_connection(host, port)
    try:
        await send_json(writer, message, padded_cell_size=cell_size)
        if verbose:
            log_debug("PROTO", f"JSON message sent to {host}:{port}")
        response = await recv_json(reader)
        if verbose:
            log_debug("PROTO", f"JSON response received from {host}:{port}")
        return response
    finally:
        await safe_close_writer(writer, "PROTO", verbose=verbose)
        if verbose:
            log_debug("PROTO", f"JSON round-trip connection to {host}:{port} closed")
