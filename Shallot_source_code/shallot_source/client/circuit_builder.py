"""Build onion packets for a runtime-selected circuit.

The base route is:
    ENTRY -> OFFICIAL MIDDLE -> EXIT

When Contributor Path is enabled, the route becomes:
    ENTRY -> OFFICIAL MIDDLE -> CONTRIBUTOR 1 -> CONTRIBUTOR 2 -> ... -> EXIT

Each hop receives its own X25519/HKDF-derived AES-GCM key. Contributors are
cryptographic middle relays and can only decrypt their own forwarding layer.
"""

from shared.crypto_utils import encrypt_json, decrypt_json
from shared.config import PADDED_CELL_SIZE
from shared.key_exchange import client_make_kx
from shared.logging_utils import log_debug, log_info
from shared.security import add_replay_fields


def _padding_metadata(padding_enabled: bool, cell_size: int) -> dict | None:
    if not padding_enabled:
        return None
    return {"enabled": True, "cell_size": int(cell_size)}


def _encrypt_for_relay(payload: dict, *, circuit, relay_id: str, role: str, public_key_b64: str):
    kx, key = client_make_kx(public_key_b64, circuit_id=circuit.circuit_id, relay_id=relay_id, role=role)
    return kx, encrypt_json(key, payload, padded=False), key


def _wrap_for_runtime_circuit(exit_plain: dict, circuit, *, padding_enabled: bool = False, cell_size: int = PADDED_CELL_SIZE) -> tuple[dict, list[bytes]]:
    """Build a layered onion message and return (message, hop_keys).

    hop_keys is a list of the AES-GCM session keys in route order:
    [entry_key, middle_key, contributor1_key, ..., exit_key].
    The client uses these to decrypt the layered response returned by the relays.
    """
    action = exit_plain.get("action", "unknown")
    session_id = exit_plain.get("session_id")
    is_quiet = action in {"stream_poll", "stream_data", "stream_close"}

    if not is_quiet:
        log_info("CIRCUIT", f"Building onion layers for action = {action}", session=session_id)

    # Innermost exit layer.
    exit_plain = add_replay_fields(exit_plain)
    next_kx, next_layer_b64, exit_key = _encrypt_for_relay(
        exit_plain,
        circuit=circuit,
        relay_id=circuit.exit_id,
        role="exit",
        public_key_b64=circuit.exit_public_key_b64,
    )
    next_host = circuit.exit_host
    next_port = circuit.exit_port
    if not is_quiet:
        log_debug("CIRCUIT", f"Exit layer encrypted for EXIT relay at {circuit.exit_host}:{circuit.exit_port}", session=session_id, force=True)

    # Collect keys in route order; we'll prepend entry/middle later.
    # Start with contributor keys (in route order), then exit key at the end.
    contributor_keys = []

    # Contributor layers. We wrap in reverse order so the first contributor in
    # the route receives the outermost contributor layer.
    contributors = list(getattr(circuit, "contributors", tuple()))
    for index_from_end, contributor in enumerate(reversed(contributors), start=1):
        contributor_plain = {
            "next_host": next_host,
            "next_port": next_port,
            "payload": next_layer_b64,
            "next_kx": next_kx,
            "action": action,
            "session_id": session_id,
        }
        contributor_plain = add_replay_fields(contributor_plain)
        contributor_kx, contributor_layer_b64, contrib_key = _encrypt_for_relay(
            contributor_plain,
            circuit=circuit,
            relay_id=contributor.relay_id,
            role="middle",
            public_key_b64=contributor.public_key_b64,
        )
        contributor_keys.insert(0, contrib_key)  # insert at front to maintain route order
        next_kx = contributor_kx
        next_layer_b64 = contributor_layer_b64
        next_host = contributor.host
        next_port = contributor.port
        if not is_quiet:
            # Display route order, not reverse wrapping order.
            route_index = len(contributors) - index_from_end + 1
            log_debug("CIRCUIT", f"Contributor {route_index} layer encrypted for {contributor.relay_id} at {contributor.host}:{contributor.port}", session=session_id, force=True)

    # Official middle layer. It forwards either to first contributor or directly
    # to exit if Contributor Path is off/no contributors are online.
    middle_plain = {
        "next_host": next_host,
        "next_port": next_port,
        "payload": next_layer_b64,
        "next_kx": next_kx,
        "action": action,
        "session_id": session_id,
    }
    middle_plain = add_replay_fields(middle_plain)
    middle_kx, middle_layer_b64, middle_key = _encrypt_for_relay(
        middle_plain,
        circuit=circuit,
        relay_id=circuit.middle_id,
        role="middle",
        public_key_b64=circuit.middle_public_key_b64,
    )
    if not is_quiet:
        log_debug("CIRCUIT", f"Official middle layer encrypted for MIDDLE relay at {circuit.middle_host}:{circuit.middle_port}", session=session_id, force=True)

    # Outermost entry layer.
    entry_plain = {
        "next_host": circuit.middle_host,
        "next_port": circuit.middle_port,
        "payload": middle_layer_b64,
        "next_kx": middle_kx,
        "action": action,
        "session_id": session_id,
    }
    entry_plain = add_replay_fields(entry_plain)
    entry_kx, entry_layer_b64, entry_key = _encrypt_for_relay(
        entry_plain,
        circuit=circuit,
        relay_id=circuit.entry_id,
        role="entry",
        public_key_b64=circuit.entry_public_key_b64,
    )
    if not is_quiet:
        log_debug("CIRCUIT", f"Entry layer encrypted for ENTRY relay at {circuit.entry_host}:{circuit.entry_port}", session=session_id, force=True)
        if padding_enabled:
            log_info("CIRCUIT", f"Uniform transport padding enabled: every onion-link frame = {int(cell_size)} bytes", session=session_id)
        log_info("CIRCUIT", "Onion packet build complete", session=session_id)

    message = {"type": "onion", "layer_b64": entry_layer_b64, "kx": entry_kx, "quiet": is_quiet}
    padding = _padding_metadata(padding_enabled, cell_size)
    if padding:
        message["padding"] = padding

    # Keys in route order: entry, middle, [contributors...], exit
    hop_keys = [entry_key, middle_key] + contributor_keys + [exit_key]
    return message, hop_keys


def build_onion_http_request(dest_host: str, dest_port: int, raw_http_request: bytes, circuit, *, padding_enabled: bool = False, cell_size: int = PADDED_CELL_SIZE) -> tuple[dict, list[bytes]]:
    log_info("CIRCUIT", "Building onion layers for runtime HTTP route")
    log_info("CIRCUIT", f"Final destination = {dest_host}:{dest_port}")
    log_info("CIRCUIT", f"Exit layer plaintext created ({len(raw_http_request)} request bytes)")
    exit_plain = {"action": "exit_request", "dest_host": dest_host, "dest_port": dest_port, "request_hex": raw_http_request.hex()}
    return _wrap_for_runtime_circuit(exit_plain, circuit, padding_enabled=padding_enabled, cell_size=cell_size)


def build_onion_tunnel_open(dest_host: str, dest_port: int, session_id: str, circuit, *, padding_enabled: bool = False, cell_size: int = PADDED_CELL_SIZE) -> tuple[dict, list[bytes]]:
    log_info("CIRCUIT", "Building tunnel-open onion packet", session=session_id)
    log_info("CIRCUIT", f"CONNECT destination = {dest_host}:{dest_port}", session=session_id)
    exit_plain = {"action": "stream_open", "dest_host": dest_host, "dest_port": dest_port, "session_id": session_id}
    return _wrap_for_runtime_circuit(exit_plain, circuit, padding_enabled=padding_enabled, cell_size=cell_size)


def build_onion_tunnel_data(session_id: str, chunk: bytes, circuit, *, padding_enabled: bool = False, cell_size: int = PADDED_CELL_SIZE) -> tuple[dict, list[bytes]]:
    exit_plain = {"action": "stream_data", "session_id": session_id, "data_hex": chunk.hex()}
    return _wrap_for_runtime_circuit(exit_plain, circuit, padding_enabled=padding_enabled, cell_size=cell_size)


def build_onion_tunnel_poll(session_id: str, circuit, *, padding_enabled: bool = False, cell_size: int = PADDED_CELL_SIZE) -> tuple[dict, list[bytes]]:
    exit_plain = {"action": "stream_poll", "session_id": session_id}
    return _wrap_for_runtime_circuit(exit_plain, circuit, padding_enabled=padding_enabled, cell_size=cell_size)


def build_onion_tunnel_close(session_id: str, circuit, *, padding_enabled: bool = False, cell_size: int = PADDED_CELL_SIZE) -> tuple[dict, list[bytes]]:
    log_info("CIRCUIT", f"Close packet queued on {circuit.route_summary}", session=session_id)
    exit_plain = {"action": "stream_close", "session_id": session_id}
    return _wrap_for_runtime_circuit(exit_plain, circuit, padding_enabled=padding_enabled, cell_size=cell_size)


def unwrap_response(response: dict, hop_keys: list[bytes]) -> dict:
    """Decrypt a layered response returned by the relay chain.

    Each relay wraps the response in one AES-GCM encryption layer using the
    same session key that was used to decrypt the request. The layers are
    applied in route order (entry wraps last, so its layer is outermost),
    so we peel them in the same order: entry key first, then middle, then
    any contributors, then exit.
    """
    hop_labels = ["entry", "middle"] + [f"contributor-{i+1}" for i in range(len(hop_keys) - 3)] + ["exit"] if len(hop_keys) >= 3 else [f"hop-{i+1}" for i in range(len(hop_keys))]
    current = response
    for i, key in enumerate(hop_keys):
        encrypted_b64 = current.get("encrypted_response_b64")
        if encrypted_b64 is None:
            # Response was not encrypted at this layer (e.g. error before
            # encryption could be applied). Return as-is.
            return current
        label = hop_labels[i] if i < len(hop_labels) else f"hop-{i+1}"
        log_debug("CIRCUIT", f"Unwrapping response layer {i+1}/{len(hop_keys)} ({label}): {len(encrypted_b64)} chars of ciphertext")
        current = decrypt_json(key, encrypted_b64)
    log_debug("CIRCUIT", f"All {len(hop_keys)} response layers decrypted successfully")
    return current
