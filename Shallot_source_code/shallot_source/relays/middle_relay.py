import asyncio
import os
from asyncio import IncompleteReadError

from relays.relay_common import decrypt_relay_layer, decrypt_relay_layer_with_key, relay_packet, make_connection_limiter
from shared.config import MIDDLE_HOP
from shared.key_exchange import load_or_create_local_relay_keys
from shared.logging_utils import log_debug, log_error, log_info
from shared.protocol import recv_json, send_json, safe_close_writer, padding_cell_size_from_message

RELAY_HOST = os.getenv("RELAY_HOST", MIDDLE_HOP.host)
RELAY_PORT = int(os.getenv("RELAY_PORT", str(MIDDLE_HOP.port)))
RELAY_NAME = os.getenv("RELAY_NAME", "middle1")
TAG = f"MIDDLE-{RELAY_NAME}"

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
        # Decrypt once and reuse — see entry_relay.py for rationale.
        inner = None
        middle_key = None
        if message.get("type") == "onion" and "layer_b64" in message:
            try:
                inner, middle_key = decrypt_relay_layer_with_key(message, RELAY_NAME, "middle")
                session = inner.get("session_id")
            except Exception:
                inner = None
                middle_key = None
                session = None
        if not quiet:
            prev_hop_ip = peer[0] if isinstance(peer, tuple) else str(peer)
            log_info(TAG, f"Accepted packet from previous hop ({prev_hop_ip})", session=session)

        if message.get("type") != "onion":
            await send_json(writer, {"ok": False, "error": "relay_error", "code": "unsupported_message_type"}, padded_cell_size=response_cell_size)
            return

        response = await relay_packet(message, TAG, RELAY_NAME, "middle", inner=inner, relay_key=middle_key)
        await send_json(writer, response, padded_cell_size=response_cell_size)
        if not quiet:
            prev_hop_ip = peer[0] if isinstance(peer, tuple) else str(peer)
            has_encrypted = "encrypted_response_b64" in response
            log_info(TAG, f"Encrypted response sent to previous hop ({prev_hop_ip}) | encrypted={has_encrypted}", session=session)
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

    public_host = os.getenv("RELAY_PUBLIC_HOST", "").strip() or RELAY_HOST
    if public_host == "0.0.0.0":
        public_host = "127.0.0.1"
    from shared.relay_registration import run_official_relay_registration_loop
    asyncio.create_task(
        run_official_relay_registration_loop(
            relay_id=RELAY_NAME,
            public_host=public_host,
            port=RELAY_PORT,
            role="middle",
        )
    )

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
