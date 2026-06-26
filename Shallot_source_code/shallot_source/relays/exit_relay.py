import asyncio
import errno
import os
import socket
import time
from asyncio import IncompleteReadError
from dataclasses import dataclass, field
from typing import Dict

from relays.relay_common import decrypt_relay_layer, decrypt_relay_layer_with_key, make_connection_limiter
from shared.config import (
    EXIT_HOP,
    STREAM_READ_SIZE,
    STREAM_READ_TIMEOUT,
    EXIT_POLL_LOG_EVERY,
    EXIT_SESSION_IDLE_TIMEOUT_SECONDS,
    EXIT_SESSION_CLEANUP_INTERVAL_SECONDS,
    EXIT_HTTP_RESPONSE_MAX_BYTES,
    EXIT_HTTP_RESPONSE_TIMEOUT_SECONDS,
)
from shared.crypto_utils import encrypt_json
from shared.key_exchange import load_or_create_local_relay_keys
from shared.logging_utils import log_debug, log_error, log_info
from shared.protocol import (
    recv_json,
    send_json,
    b64_encode_bytes,
    safe_close_writer,
    padding_cell_size_from_message,
)
from shared.security import validate_replay_fields

RELAY_HOST = os.getenv("RELAY_HOST", EXIT_HOP.host)
RELAY_PORT = int(os.getenv("RELAY_PORT", str(EXIT_HOP.port)))
RELAY_NAME = os.getenv("RELAY_NAME", "exit1")
TAG = f"EXIT-{RELAY_NAME}"

CONN_LIMITER = make_connection_limiter()


def generic_error(code: str = "relay_error") -> dict:
    return {"ok": False, "error": "relay_error", "code": code}


@dataclass
class TunnelSession:
    session_id: str
    dest_host: str
    dest_port: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    bytes_to_dest: int = 0
    bytes_from_dest: int = 0
    polls: int = 0
    empty_polls: int = 0
    last_activity: float = field(default_factory=time.time)


TUNNEL_SESSIONS: Dict[str, TunnelSession] = {}


def enrich_destination_error(dest_host: str, dest_port: int, exc: Exception) -> str:
    base = str(exc) if str(exc).startswith(f"{TAG} server error:") else f"{TAG} server error: {exc}"
    text = str(exc).lower()
    if isinstance(exc, socket.gaierror) or "getaddrinfo failed" in text:
        if dest_host.startswith("ipv6.") or ".ipv6." in dest_host:
            return f"{base} | DNS lookup failed for an IPv6 probe host ({dest_host}:{dest_port}). This does not usually indicate a relay failure."
        return f"{base} | DNS lookup failed for {dest_host}:{dest_port}."
    if isinstance(exc, OSError) and getattr(exc, "errno", None) in {
        errno.ECONNRESET,
        errno.ECONNABORTED,
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
    }:
        return f"{base} | Destination connection failed for {dest_host}:{dest_port}."
    return base


async def open_destination(dest_host: str, dest_port: int):
    try:
        return await asyncio.open_connection(dest_host, dest_port)
    except Exception as exc:
        raise RuntimeError(enrich_destination_error(dest_host, dest_port, exc)) from exc


async def fetch_http_response(dest_host: str, dest_port: int, raw_request: bytes) -> bytes:
    log_debug(TAG, f"Opening TCP connection to {dest_host}:{dest_port}")
    reader, writer = await open_destination(dest_host, dest_port)
    try:
        log_debug(TAG, f"Forwarding {len(raw_request)} request bytes")
        writer.write(raw_request)
        await writer.drain()
        chunks: list[bytes] = []
        total = 0
        deadline = asyncio.get_event_loop().time() + EXIT_HTTP_RESPONSE_TIMEOUT_SECONDS
        truncated = False

        while True:
            time_left = deadline - asyncio.get_event_loop().time()
            if time_left <= 0:
                log_error(TAG, "Destination response exceeded overall timeout; closing read")
                truncated = True
                break
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=time_left)
            except asyncio.TimeoutError:
                log_error(TAG, "Destination response exceeded overall timeout; closing read")
                truncated = True
                break
            if not chunk:
                break

            remaining_capacity = EXIT_HTTP_RESPONSE_MAX_BYTES - total
            if len(chunk) > remaining_capacity:
                # Stop accepting data past the configured cap. We do not raise
                # because some of the response body may still be useful to the
                # client; we simply truncate and let the caller see what fits.
                if remaining_capacity > 0:
                    chunks.append(chunk[:remaining_capacity])
                    total += remaining_capacity
                log_error(
                    TAG,
                    f"Destination response exceeded {EXIT_HTTP_RESPONSE_MAX_BYTES} byte cap; truncating",
                )
                truncated = True
                break

            chunks.append(chunk)
            total += len(chunk)

        log_debug(TAG, f"Read {total} bytes back from destination" + (" (truncated)" if truncated else ""))
        return b"".join(chunks)
    finally:
        await safe_close_writer(writer, TAG, verbose=False)


async def open_tunnel(session_id: str, dest_host: str, dest_port: int) -> dict:
    if session_id in TUNNEL_SESSIONS:
        log_debug(TAG, "Reusing existing tunnel state", session=session_id)
        return {"ok": True, "status": "already_open"}

    # Privacy: destination hostname is logged at debug level only. At info
    # level we still record that *a* tunnel was opened, but not where to.
    # An exit relay should not keep a long-term log of who-asked-for-what
    # because that data, if stolen, partially defeats the network's purpose.
    log_debug(TAG, f"Opening CONNECT tunnel to {dest_host}:{dest_port}", session=session_id)
    log_info(TAG, "Opening CONNECT tunnel", session=session_id)
    reader, writer = await open_destination(dest_host, dest_port)
    TUNNEL_SESSIONS[session_id] = TunnelSession(session_id, dest_host, dest_port, reader, writer)
    log_info(TAG, "Tunnel opened successfully", session=session_id)
    return {"ok": True, "status": "opened"}


async def close_tunnel(session_id: str) -> dict:
    session = TUNNEL_SESSIONS.pop(session_id, None)
    if session is None:
        return {"ok": True, "status": "already_closed"}

    await safe_close_writer(session.writer, TAG, verbose=False)
    log_info(
        TAG,
        f"Tunnel closed | to-destination={session.bytes_to_dest} bytes, from-destination={session.bytes_from_dest} bytes, polls={session.polls}, empty-polls={session.empty_polls}",
        session=session_id,
    )
    return {"ok": True, "status": "closed"}


async def tunnel_write(session_id: str, data: bytes, quiet: bool = False) -> dict:
    session = TUNNEL_SESSIONS.get(session_id)
    if session is None:
        return generic_error("unknown_tunnel_session")
    try:
        session.last_activity = time.time()
        session.writer.write(data)
        await session.writer.drain()
        session.bytes_to_dest += len(data)
        return {"ok": True, "status": "written", "written_bytes": len(data)}
    except Exception as exc:
        enriched = enrich_destination_error(session.dest_host, session.dest_port, exc)
        log_error(TAG, enriched, session=session_id)
        await close_tunnel(session_id)
        return generic_error("destination_write_failed")


async def tunnel_read_available(session_id: str, quiet: bool = False, padded_cell_size: int | None = None) -> dict:
    session = TUNNEL_SESSIONS.get(session_id)
    if session is None:
        return generic_error("unknown_tunnel_session")

    chunks: list[bytes] = []
    total = 0
    eof = False
    max_chunks_this_poll = 1 if padded_cell_size else None

    while True:
        try:
            chunk = await asyncio.wait_for(session.reader.read(STREAM_READ_SIZE), timeout=STREAM_READ_TIMEOUT)
        except asyncio.TimeoutError:
            session.polls += 1
            session.empty_polls += 1
            if (not quiet) and session.empty_polls % EXIT_POLL_LOG_EVERY == 0:
                log_debug(TAG, f"Idle poll x{session.empty_polls}", session=session_id)
            break
        except Exception as exc:
            enriched = enrich_destination_error(session.dest_host, session.dest_port, exc)
            log_error(TAG, enriched, session=session_id)
            await close_tunnel(session_id)
            return generic_error("destination_read_failed")

        if not chunk:
            session.polls += 1
            eof = True
            break

        session.last_activity = time.time()
        chunks.append(chunk)
        total += len(chunk)
        session.polls += 1
        session.bytes_from_dest += len(chunk)
        session.empty_polls = 0

        if max_chunks_this_poll is not None and len(chunks) >= max_chunks_this_poll:
            break
        if len(chunk) < STREAM_READ_SIZE:
            break

    response = {"ok": True, "data_b64": b64_encode_bytes(b"".join(chunks)), "eof": eof, "read_bytes": total}
    if eof:
        await close_tunnel(session_id)
    return response


async def handle_exit_action(final_layer: dict, quiet: bool = False, padded_cell_size: int | None = None) -> dict:
    action = final_layer.get("action")
    session_id = final_layer.get("session_id")
    if not quiet and action != "stream_poll":
        log_debug(TAG, f"Final layer action = {action}", session=session_id)

    try:
        if action == "exit_request":
            dest_host = final_layer["dest_host"]
            dest_port = int(final_layer["dest_port"])
            raw_request = bytes.fromhex(final_layer["request_hex"])
            # Privacy: the destination is debug-only; info level just records
            # that an HTTP request happened. See open_tunnel for rationale.
            log_debug(TAG, f"HTTP destination = {dest_host}:{dest_port}", session=session_id)
            log_info(TAG, "HTTP request forwarded", session=session_id)
            response_bytes = await fetch_http_response(dest_host, dest_port, raw_request)
            log_info(TAG, f"Destination response received ({len(response_bytes)} bytes)")
            return {"ok": True, "response_b64": b64_encode_bytes(response_bytes)}
        if action == "stream_open":
            return await open_tunnel(session_id, final_layer["dest_host"], int(final_layer["dest_port"]))
        if action == "stream_data":
            return await tunnel_write(session_id, bytes.fromhex(final_layer.get("data_hex", "")), quiet=quiet)
        if action == "stream_poll":
            return await tunnel_read_available(session_id, quiet=quiet, padded_cell_size=padded_cell_size)
        if action == "stream_close":
            return await close_tunnel(session_id)
        return generic_error("unsupported_exit_action")
    except Exception as exc:
        log_error(TAG, f"Exit action failed: {exc}", session=session_id)
        return generic_error("exit_action_failed")


async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername")
    if not CONN_LIMITER.check_rate_limit(peer):
        log_error(TAG, f"Rate-limit reject from {peer}")
        try:
            await send_json(writer, generic_error("rate_limited"))
        except Exception:
            pass
        await safe_close_writer(writer, TAG, verbose=False)
        return
    async with CONN_LIMITER.semaphore:
        await _handle_client_impl(reader, writer, peer)


async def _handle_client_impl(reader, writer, peer):
    quiet = False
    session = None
    response_cell_size = None
    try:
        message = await recv_json(reader)
        quiet = bool(message.get("quiet", False))
        response_cell_size = padding_cell_size_from_message(message)
        if message.get("type") != "onion":
            await send_json(writer, generic_error("unsupported_message_type"), padded_cell_size=response_cell_size)
            return

        final_layer, exit_key = decrypt_relay_layer_with_key(message, RELAY_NAME, "exit")
        validate_replay_fields(RELAY_NAME, final_layer)
        session = final_layer.get("session_id")
        action = final_layer.get("action", "unknown")
        prev_hop_ip = peer[0] if isinstance(peer, tuple) else str(peer)
        if not quiet:
            log_info(TAG, f"Accepted packet from previous hop ({prev_hop_ip}) | action={action}", session=session)
        response = await handle_exit_action(final_layer, quiet=quiet, padded_cell_size=response_cell_size)

        # Wrap the response in an encryption layer using this relay's session key.
        encrypted_response_b64 = encrypt_json(exit_key, response)
        encrypted_response = {"ok": True, "encrypted_response_b64": encrypted_response_b64}
        if not quiet:
            log_info(TAG, f"Response encrypted for upstream ({len(encrypted_response_b64)} chars of ciphertext)", session=session)

        await send_json(writer, encrypted_response, padded_cell_size=response_cell_size)
        if not quiet:
            log_info(TAG, f"Encrypted response sent to previous hop ({prev_hop_ip})", session=session)
    except IncompleteReadError as exc:
        if exc.partial:
            log_debug(TAG, f"Incomplete framed message from {peer}", session=session)
    except asyncio.CancelledError:
        log_debug(TAG, "Connection task cancelled", session=session)
        raise
    except Exception as exc:
        log_error(TAG, f"Server error: {exc}", session=session)
        try:
            await send_json(writer, generic_error("exit_handler_error"), padded_cell_size=response_cell_size)
        except Exception:
            pass
    finally:
        await safe_close_writer(writer, TAG, verbose=False)


async def cleanup_idle_tunnel_sessions() -> None:
    while True:
        await asyncio.sleep(EXIT_SESSION_CLEANUP_INTERVAL_SECONDS)
        now = time.time()
        for session_id, session in list(TUNNEL_SESSIONS.items()):
            if now - (session.last_activity or now) >= EXIT_SESSION_IDLE_TIMEOUT_SECONDS:
                log_info(TAG, "Idle tunnel timeout reached; closing abandoned session", session=session_id)
                await close_tunnel(session_id)


async def main() -> None:
    load_or_create_local_relay_keys()
    from shared.security import start_directory_refresher
    start_directory_refresher()
    cleanup_task = asyncio.create_task(cleanup_idle_tunnel_sessions())
    server = await asyncio.start_server(handle_client, RELAY_HOST, RELAY_PORT)
    log_info(TAG, f"Listening on {RELAY_HOST}:{RELAY_PORT}")
    log_info(TAG, "Waiting for onion packets...")

    public_host = os.getenv("RELAY_PUBLIC_HOST", "").strip() or RELAY_HOST
    if public_host == "0.0.0.0":
        public_host = "127.0.0.1"
    from shared.relay_registration import run_official_relay_registration_loop
    registration_task = asyncio.create_task(
        run_official_relay_registration_loop(
            relay_id=RELAY_NAME,
            public_host=public_host,
            port=RELAY_PORT,
            role="exit",
        )
    )

    async with server:
        try:
            await server.serve_forever()
        finally:
            cleanup_task.cancel()
            registration_task.cancel()
            await asyncio.gather(cleanup_task, registration_task, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
