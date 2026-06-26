import asyncio
import os
from asyncio import IncompleteReadError

from relays.relay_common import decrypt_relay_layer, decrypt_relay_layer_with_key, relay_packet, make_connection_limiter
from shared.config import ENTRY_HOP
from shared.key_exchange import load_or_create_local_relay_keys
from shared.logging_utils import log_debug, log_error, log_info
from shared.protocol import recv_json, send_json, safe_close_writer, padding_cell_size_from_message

RELAY_HOST = os.getenv("RELAY_HOST", ENTRY_HOP.host)
RELAY_PORT = int(os.getenv("RELAY_PORT", str(ENTRY_HOP.port)))
RELAY_NAME = os.getenv("RELAY_NAME", "entry1")
TAG = f"ENTRY-{RELAY_NAME}"

CONN_LIMITER = make_connection_limiter()


async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername")
    if not CONN_LIMITER.check_rate_limit(peer):
        log_error(TAG, f"Rate-limit reject from {peer}")
        try:
            await send_json(writer, {"ok": False, "error": "relay_error", "code": "rate_limited"})
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
        # Decrypt the layer once and reuse it: previously this handler
        # decrypted to read session_id for logging, and relay_packet then
        # decrypted again to do the actual forwarding. With padded cells
        # that's a real per-packet cost (AES-GCM + JSON parse). One decrypt
        # is sufficient.
        inner = None
        entry_key = None
        if message.get("type") == "onion" and "layer_b64" in message:
            try:
                inner, entry_key = decrypt_relay_layer_with_key(message, RELAY_NAME, "entry")
                session = inner.get("session_id")
            except Exception:
                inner = None
                entry_key = None
                session = None
        if not quiet:
            client_ip = peer[0] if isinstance(peer, tuple) else str(peer)
            log_info(TAG, f"Accepted packet from client {client_ip}", session=session)

        if message.get("type") != "onion":
            await send_json(writer, {"ok": False, "error": "relay_error", "code": "unsupported_message_type"}, padded_cell_size=response_cell_size)
            return

        response = await relay_packet(message, TAG, RELAY_NAME, "entry", inner=inner, relay_key=entry_key)
        await send_json(writer, response, padded_cell_size=response_cell_size)
        if not quiet:
            has_encrypted = "encrypted_response_b64" in response
            log_info(TAG, f"Encrypted response sent to client {client_ip} | encrypted={has_encrypted}", session=session)
    except IncompleteReadError as exc:
        if exc.partial:
            log_debug(TAG, f"Incomplete framed message from {peer}", session=session)
    except asyncio.CancelledError:
        log_debug(TAG, "Connection task cancelled", session=session)
        raise
    except Exception as exc:
        log_error(TAG, f"Server error: {exc}", session=session)
        try:
            await send_json(writer, {"ok": False, "error": "relay_error", "code": "relay_handler_error"}, padded_cell_size=response_cell_size)
        except Exception:
            pass
    finally:
        await safe_close_writer(writer, TAG, verbose=False)


async def main() -> None:
    load_or_create_local_relay_keys()
    from shared.security import start_directory_refresher
    start_directory_refresher()
    server = await asyncio.start_server(handle_client, RELAY_HOST, RELAY_PORT)
    log_info(TAG, f"Listening on {RELAY_HOST}:{RELAY_PORT}")
    log_info(TAG, "Waiting for onion packets...")

    # Register with the directory server and heartbeat in the background.
    # The directory server only knows about this relay if we tell it, the
    # same way contributors do. RELAY_PUBLIC_HOST is what we advertise to
    # other machines; if not set, fall back to the bind address (only
    # useful for single-machine demos).
    public_host = os.getenv("RELAY_PUBLIC_HOST", "").strip() or RELAY_HOST
    if public_host == "0.0.0.0":
        public_host = "127.0.0.1"  # last resort if neither is configured
    from shared.relay_registration import run_official_relay_registration_loop
    asyncio.create_task(
        run_official_relay_registration_loop(
            relay_id=RELAY_NAME,
            public_host=public_host,
            port=RELAY_PORT,
            role="entry",
        )
    )

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
