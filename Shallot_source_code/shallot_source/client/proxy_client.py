"""client/proxy_client.py

Local onion client / browser proxy.

Supports:
- normal HTTP proxy requests (GET/HEAD/etc. over http://)
- HTTPS browsing via CONNECT tunneling
- local control API for extension/UI integration
- runtime session/stat tracking
"""

import asyncio
import ipaddress
import re
import time
import uuid
from urllib.parse import urlsplit

from client.circuit_builder import (
    build_onion_http_request,
    build_onion_tunnel_open,
    build_onion_tunnel_data,
    build_onion_tunnel_poll,
    build_onion_tunnel_close,
    unwrap_response,
)
from client.client_state import ClientRuntimeState
from client.control_api import start_control_api
from shared.config import (
    CLIENT_PROXY_HOST,
    CLIENT_PROXY_PORT,
    TUNNEL_POLL_INTERVAL,
    TUNNEL_IDLE_LOG_EVERY,
    TUNNEL_BROWSER_EOF_DRAIN_SECONDS,
    TUNNEL_POST_CLOSE_GRACE_SECONDS,
    MAX_STREAM_CHUNK_SIZE,
    HTTP_REQUEST_HEADERS_MAX_BYTES,
    HTTP_REQUEST_BODY_MAX_BYTES,
    HTTP_REQUEST_BODY_READ_TIMEOUT_SECONDS,
    EXIT_HTTP_RESPONSE_TIMEOUT_SECONDS_NO_DATA,
)
from shared.protocol import round_trip_json, b64_decode_bytes, safe_close_writer
from shared.logging_utils import log_debug, log_error, log_info, human_bytes, human_duration


RUNTIME = ClientRuntimeState()
LAST_DISABLED_LOG_AT = 0.0


def forward_route(circuit, destination: str | None = None) -> str:
    parts = ["CLIENT", f"ENTRY({circuit.entry_id}:{circuit.entry_port})", f"MIDDLE({circuit.middle_id}:{circuit.middle_port})"]
    # Walk the full contributor chain (1, 2, or 3 hops) rather than just
    # logging the first contributor. The previous version used the singular
    # circuit.contributor_id helper which returns only contributors[0],
    # so multi-hop contributor paths were under-reported in the logs.
    for index, hop in enumerate(getattr(circuit, "contributors", ()) or (), start=1):
        parts.append(f"CONTRIBUTOR{index}({hop.relay_id}:{hop.port})")
    parts.append(f"EXIT({circuit.exit_id}:{circuit.exit_port})")
    if destination:
        parts.append(destination)
    return " -> ".join(parts)


def reverse_route(circuit, destination: str) -> str:
    parts = [destination, f"EXIT({circuit.exit_id}:{circuit.exit_port})"]
    # Reverse path: contributors traversed in opposite order to the forward path.
    contributors = list(getattr(circuit, "contributors", ()) or ())
    total = len(contributors)
    for index_from_end, hop in enumerate(reversed(contributors), start=1):
        forward_index = total - index_from_end + 1
        parts.append(f"CONTRIBUTOR{forward_index}({hop.relay_id}:{hop.port})")
    parts.extend([f"MIDDLE({circuit.middle_id}:{circuit.middle_port})", f"ENTRY({circuit.entry_id}:{circuit.entry_port})", "CLIENT"])
    return " -> ".join(parts)


async def auto_rotate_loop() -> None:
    """Background task that rebuilds the circuit when:
      * the rotation timer fires (default every 5 minutes), OR
      * any relay in the current circuit becomes offline or vanishes from
        the directory (e.g. a contributor's VM was shut down). The latter
        check is what makes a contributor-path circuit recover gracefully
        when the contributor disappears: the next browser request lands
        on a fresh, working circuit instead of failing over and over.
      * the initial circuit could not be built at startup (directory was
        empty or unreachable). In that case we keep retrying every loop
        iteration so the client recovers automatically once the directory
        becomes reachable.
    """
    last_health_log = 0.0
    last_no_circuit_log = 0.0
    while True:
        await asyncio.sleep(1)
        if not RUNTIME.auto_rotate_enabled:
            continue

        # Recovery path: if we have no current circuit (initial build
        # failed due to empty directory), try to build one.
        if RUNTIME.current_circuit is None:
            try:
                circuit_id = RUNTIME.new_circuit()
                log_info("CLIENT", f"Initial circuit built: {circuit_id}")
                RUNTIME.log_state_summary("Initial circuit ready")
            except ValueError as exc:
                now = time.time()
                if now - last_no_circuit_log >= 10.0:
                    log_info("CLIENT", f"Still cannot build a circuit: {exc}. Will keep retrying.")
                    last_no_circuit_log = now
            continue

        # Time-based rotation (existing behavior).
        if RUNTIME.seconds_until_rotation() <= 0:
            old = RUNTIME.current_circuit.circuit_id
            try:
                new = RUNTIME.new_circuit()
                log_info("CLIENT", f"Circuit rotated automatically: {old} -> {new}")
                RUNTIME.log_state_summary("Automatic circuit rotation")
            except ValueError as exc:
                log_error("CLIENT", f"Circuit rotation failed: {exc}; keeping previous circuit.")
            continue

        # Health-based rotation: if any relay in the circuit is no longer
        # online, rebuild now so the next browser request gets a usable
        # path. We pass force_contributor_path_off so the immediate
        # replacement falls back to the official path; the next regular
        # time-based rotation will re-introduce contributor path mode if
        # contributors that are actually online are available.
        ok, reason = RUNTIME.is_current_circuit_healthy()
        if not ok:
            now = time.time()
            if now - last_health_log >= 5.0:
                log_info("CLIENT", f"Active circuit no longer healthy: {reason}; rebuilding (contributor path off this time).")
                last_health_log = now
            old = RUNTIME.current_circuit.circuit_id
            try:
                new = RUNTIME.new_circuit(force_contributor_path_off=True)
                if new != old:
                    log_info("CLIENT", f"Circuit rebuilt due to relay health: {old} -> {new}")
            except ValueError as exc:
                log_error("CLIENT", f"Health-driven rebuild failed: {exc}; keeping previous circuit.")


async def read_browser_request_headers(reader: asyncio.StreamReader) -> tuple[bytes, bytes]:
    """Read up to and including the end-of-headers marker.

    Returns (headers_bytes, leftover_bytes) where leftover_bytes are any bytes
    already received past the \r\n\r\n boundary (typically the start of a
    POST/PUT body). Headers are capped at HTTP_REQUEST_HEADERS_MAX_BYTES so a
    slow header stream cannot exhaust memory.
    """
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = await reader.read(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > HTTP_REQUEST_HEADERS_MAX_BYTES:
            raise ValueError("HTTP request headers too large")
    if b"\r\n\r\n" not in data:
        return data, b""
    head, _, leftover = data.partition(b"\r\n\r\n")
    headers_bytes = head + b"\r\n\r\n"
    return headers_bytes, leftover


def header_value(header_lines: list[str], name: str) -> str | None:
    """Return the value of the first matching header (case-insensitive)."""
    target = name.lower()
    for line in header_lines:
        if ":" in line:
            key, _, value = line.partition(":")
            if key.strip().lower() == target:
                return value.strip()
    return None


async def read_request_body(
    reader: asyncio.StreamReader,
    leftover: bytes,
    content_length: int,
) -> bytes:
    """Read exactly content_length body bytes, starting with any leftover bytes
    already buffered after the header section. Bounded by config caps and a
    read timeout so a stalled client cannot tie up the proxy indefinitely.
    """
    if content_length <= 0:
        return b""
    if content_length > HTTP_REQUEST_BODY_MAX_BYTES:
        raise ValueError("HTTP request body exceeds maximum allowed size")

    body = leftover[:content_length]
    remaining = content_length - len(body)
    if remaining <= 0:
        return body

    deadline = asyncio.get_event_loop().time() + HTTP_REQUEST_BODY_READ_TIMEOUT_SECONDS
    while remaining > 0:
        time_left = deadline - asyncio.get_event_loop().time()
        if time_left <= 0:
            raise ValueError("HTTP request body read timed out")
        try:
            chunk = await asyncio.wait_for(
                reader.read(min(remaining, 65536)),
                timeout=time_left,
            )
        except asyncio.TimeoutError as exc:
            raise ValueError("HTTP request body read timed out") from exc
        if not chunk:
            raise ValueError("Browser closed connection before sending full request body")
        body += chunk
        remaining -= len(chunk)
    return body



def parse_request_head(raw_request: bytes) -> tuple[str, str, str, list[str]]:
    text = raw_request.decode("iso-8859-1")
    lines = text.split("\r\n")
    if not lines or len(lines[0].split()) < 3:
        raise ValueError("Invalid HTTP request line")
    method, target, version = lines[0].split(maxsplit=2)
    header_lines = [line for line in lines[1:] if line]
    return method.upper(), target, version, header_lines



_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}\.?$")
_BAD_HOST_CHARS = set(" ,/%\\@\t\r\n")


def validate_destination_host(host: str) -> str:
    """Validate and normalize a destination hostname/IP before it enters the onion route."""
    if host is None:
        raise ValueError("Destination host is missing")
    candidate = host.strip().lower()
    if not candidate:
        raise ValueError("Destination host is empty")

    ip_candidate = candidate[1:-1] if candidate.startswith("[") and candidate.endswith("]") else candidate
    try:
        ipaddress.ip_address(ip_candidate)
        return ip_candidate
    except ValueError:
        pass

    if any(ch in candidate for ch in _BAD_HOST_CHARS):
        raise ValueError(f"Malformed destination host rejected: {host!r}")
    if candidate.startswith(".") or ".." in candidate:
        raise ValueError(f"Malformed destination host rejected: {host!r}")
    if not _HOSTNAME_RE.fullmatch(candidate):
        raise ValueError(f"Malformed destination host rejected: {host!r}")
    labels = candidate.rstrip(".").split(".")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        raise ValueError(f"Malformed destination host rejected: {host!r}")
    return candidate.rstrip(".")


def validate_destination_port(port) -> int:
    try:
        port = int(port)
    except Exception as exc:
        raise ValueError("Destination port must be an integer") from exc
    if not (1 <= port <= 65535):
        raise ValueError(f"Destination port out of range: {port}")
    return port


def parse_http_proxy_request(raw_request: bytes, body: bytes = b"") -> tuple[str, int, bytes, str, str]:
    method, target, version, header_lines = parse_request_head(raw_request)
    if method not in {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}:
        raise ValueError(f"Unsupported HTTP method for direct request mode: {method}")

    parsed = urlsplit(target)
    if parsed.scheme.lower() != "http":
        raise ValueError("Only http:// URLs are supported in direct request mode")

    dest_host = parsed.hostname
    if not dest_host:
        raise ValueError("HTTP request is missing destination host")
    try:
        dest_port = parsed.port or 80
    except ValueError as exc:
        raise ValueError("HTTP request contains an invalid destination port") from exc
    dest_host = validate_destination_host(dest_host)
    dest_port = validate_destination_port(dest_port)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    # Hop-by-hop headers (RFC 7230 §6.1) must not be forwarded by a proxy.
    # The original code only stripped Proxy-Connection / Proxy-Authorization;
    # this version drops the full standardized set plus a few client-tracking
    # headers that a privacy proxy should not relay onward.
    HOP_BY_HOP = {
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
    # Headers that can leak information about the client/network even though
    # they are not strictly hop-by-hop. Forwarded and X-Forwarded-* would
    # reveal the requester's IP to the destination if the browser ever set
    # them. Via is also stripped because including it in this prototype would
    # advertise the proxy to the destination.
    PRIVACY_DROP = {
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "via",
    }

    # The Connection header may itself list further headers that are
    # hop-by-hop for *this* request only (RFC 7230 §6.1). Parse it and add
    # those to the drop set before filtering.
    extra_drop: set[str] = set()
    for header_line in header_lines:
        if header_line.lower().startswith("connection:"):
            value = header_line.split(":", 1)[1]
            for token in value.split(","):
                token = token.strip().lower()
                if token and token not in {"close", "keep-alive"}:
                    extra_drop.add(token)

    rebuilt_lines = [f"{method} {path} {version}"]
    for header_line in header_lines:
        name = header_line.split(":", 1)[0].strip().lower() if ":" in header_line else ""
        if name in HOP_BY_HOP or name in PRIVACY_DROP or name in extra_drop:
            continue
        rebuilt_lines.append(header_line)

    rebuilt_head = ("\r\n".join(rebuilt_lines) + "\r\n\r\n").encode("iso-8859-1")
    rebuilt_request = rebuilt_head + body
    return dest_host, dest_port, rebuilt_request, method, path



def parse_connect_request(raw_request: bytes) -> tuple[str, int, str]:
    method, target, _version, _headers = parse_request_head(raw_request)
    if method != "CONNECT":
        raise ValueError(f"Not a CONNECT request: {method}")
    if ":" not in target:
        raise ValueError("CONNECT target must be host:port")
    host, port_text = target.rsplit(":", 1)
    host = validate_destination_host(host)
    port = validate_destination_port(port_text)
    return host, port, method


async def onion_round_trip(message: dict, circuit, hop_keys: list[bytes]) -> dict:
    quiet = bool(message.get("quiet", False))
    raw_response = await round_trip_json(circuit.entry_host, circuit.entry_port, message, verbose=not quiet)
    if not quiet:
        has_encrypted = "encrypted_response_b64" in raw_response
        log_debug("CLIENT", f"Raw response from entry relay | encrypted={has_encrypted}")
    return unwrap_response(raw_response, hop_keys)



def disabled_http_response() -> bytes:
    msg = "Onion routing is disabled. The local proxy is fail-closed, so this request was not sent directly to the internet."
    body = msg.encode("utf-8")
    return (
        "HTTP/1.1 503 Service Unavailable\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8") + body


async def send_tunnel_open(session_id: str, dest_host: str, dest_port: int) -> dict:
    circuit = RUNTIME.get_session_circuit(session_id)
    log_info(
        "CLIENT",
        f"Opening tunnel | {forward_route(circuit, f'{dest_host}:{dest_port}')}",
        session=session_id,
    )
    msg, hop_keys = build_onion_tunnel_open(dest_host, dest_port, session_id, circuit, padding_enabled=RUNTIME.padding_enabled, cell_size=RUNTIME.padding_cell_size)
    return await onion_round_trip(msg, circuit, hop_keys)


async def send_tunnel_data(session_id: str, chunk: bytes) -> dict:
    circuit = RUNTIME.get_session_circuit(session_id)
    msg, hop_keys = build_onion_tunnel_data(session_id, chunk, circuit, padding_enabled=RUNTIME.padding_enabled, cell_size=RUNTIME.padding_cell_size)
    return await onion_round_trip(msg, circuit, hop_keys)


async def send_tunnel_poll(session_id: str) -> dict:
    circuit = RUNTIME.get_session_circuit(session_id)
    msg, hop_keys = build_onion_tunnel_poll(session_id, circuit, padding_enabled=RUNTIME.padding_enabled, cell_size=RUNTIME.padding_cell_size)
    return await onion_round_trip(msg, circuit, hop_keys)


async def send_tunnel_close(session_id: str) -> dict:
    circuit = RUNTIME.get_session_circuit(session_id)
    msg, hop_keys = build_onion_tunnel_close(session_id, circuit, padding_enabled=RUNTIME.padding_enabled, cell_size=RUNTIME.padding_cell_size)
    return await onion_round_trip(msg, circuit, hop_keys)


async def tunnel_browser_to_exit(browser_reader, session_id: str, stop_event: asyncio.Event, browser_done_event: asyncio.Event) -> None:
    try:
        while not stop_event.is_set():
            chunk = await browser_reader.read(MAX_STREAM_CHUNK_SIZE)
            if not chunk:
                log_debug("CLIENT", "Browser closed local send side", session=session_id)
                browser_done_event.set()
                break

            RUNTIME.add_browser_bytes(session_id, len(chunk))
            session = RUNTIME.sessions.get(session_id)
            sent_total = session.bytes_from_browser if session else 0
            log_debug("CLIENT", f"Read {len(chunk)} bytes from browser (browser->dest total={sent_total})", session=session_id)

            response = await send_tunnel_data(session_id, chunk)
            if not response.get("ok"):
                error_text = response.get("error", "Unknown error")
                log_error("CLIENT", f"Tunnel data forward failed: {error_text}", session=session_id)
                RUNTIME.mark_session_error(session_id, error_text)
                stop_event.set()
                break
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log_error("CLIENT", f"Browser->exit loop error: {exc}", session=session_id)
        RUNTIME.mark_session_error(session_id, str(exc))
        stop_event.set()
    finally:
        browser_done_event.set()


async def tunnel_exit_to_browser(browser_writer, session_id: str, stop_event: asyncio.Event, browser_done_event: asyncio.Event) -> None:
    idle_polls = 0
    browser_done_at: float | None = None
    try:
        while not stop_event.is_set():
            response = await send_tunnel_poll(session_id)
            if not response.get("ok"):
                error_text = response.get("error", "Unknown error")
                log_error("CLIENT", f"Tunnel poll failed: {error_text}", session=session_id)
                RUNTIME.mark_session_error(session_id, error_text)
                stop_event.set()
                break

            data = b64_decode_bytes(response.get("data_b64", ""))
            eof = bool(response.get("eof"))

            if data:
                idle_polls = 0
                browser_done_at = None
                RUNTIME.add_return_bytes(session_id, len(data))
                session = RUNTIME.sessions.get(session_id)
                recv_total = session.bytes_to_browser if session else 0
                log_debug("CLIENT", f"Writing {len(data)} bytes back to browser (dest->browser total={recv_total})", session=session_id)
                browser_writer.write(data)
                await browser_writer.drain()

            if eof:
                log_debug("CLIENT", "Exit relay reported EOF", session=session_id)
                stop_event.set()
                break

            if not data:
                idle_polls += 1
                if browser_done_event.is_set() and browser_done_at is None:
                    browser_done_at = time.time()
                if idle_polls % (TUNNEL_IDLE_LOG_EVERY * 3) == 0:
                    log_debug("CLIENT", "Still open, waiting for remote bytes...", session=session_id)
                if browser_done_at is not None and (time.time() - browser_done_at) >= TUNNEL_BROWSER_EOF_DRAIN_SECONDS:
                    log_debug("CLIENT", "Browser send side closed and drain window expired", session=session_id)
                    stop_event.set()
                    break
                await asyncio.sleep(TUNNEL_POLL_INTERVAL)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log_error("CLIENT", f"Exit->browser loop error: {exc}", session=session_id)
        RUNTIME.mark_session_error(session_id, str(exc))
        stop_event.set()


async def handle_connect_tunnel(reader, writer, dest_host: str, dest_port: int) -> None:
    session_id = uuid.uuid4().hex
    destination = f"{dest_host}:{dest_port}"

    session_circuit = RUNTIME.current_circuit
    if session_circuit is None:
        msg = (
            "Onion network has no active circuit yet (directory not populated). "
            "Check the popup's 'Directory not live' banner for the specific reason."
        )
        log_error("CLIENT", msg, session=session_id)
        body = msg.encode("utf-8")
        writer.write(
            b"HTTP/1.1 503 Service Unavailable\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        await writer.drain()
        return
    RUNTIME.create_session(session_id, "connect", destination, circuit=session_circuit)

    log_info("CLIENT", "CONNECT tunnel requested", session=session_id)
    log_info("CLIENT", f"Destination = {destination}", session=session_id)
    log_info(
        "CLIENT",
        forward_route(session_circuit, destination),
        session=session_id,
    )

    open_response = await send_tunnel_open(session_id, dest_host, dest_port)
    if not open_response.get("ok"):
        error_text = open_response.get("error", "CONNECT open failed")
        log_error("CLIENT", f"Tunnel open failed: {error_text}", session=session_id)
        RUNTIME.mark_session_error(session_id, error_text)
        # Same recovery as the HTTP error path: refresh directory, count
        # consecutive failures, force a rebuild after the threshold.
        try:
            from shared.security import request_directory_refresh
            request_directory_refresh()
        except Exception:
            pass
        if RUNTIME.record_circuit_failure():
            old = RUNTIME.current_circuit.circuit_id
            new = RUNTIME.new_circuit(force_contributor_path_off=True)
            log_info(
                "CLIENT",
                f"Force-rebuilt circuit (contributor path off this time) after {RUNTIME._failure_threshold_for_rebuild} consecutive tunnel-open failures: {old} -> {new}",
            )
        response = (
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(error_text.encode('utf-8'))}\r\n"
            "Connection: close\r\n\r\n"
            f"{error_text}"
        ).encode("utf-8")
        writer.write(response)
        await writer.drain()
        return

    RUNTIME.mark_session_open(session_id)
    RUNTIME.record_circuit_success()
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    log_info("CLIENT", "Sent 200 Connection Established to browser", session=session_id)

    stop_event = asyncio.Event()
    browser_done_event = asyncio.Event()
    RUNTIME.register_session_stop_event(session_id, stop_event)
    browser_to_exit = asyncio.create_task(tunnel_browser_to_exit(reader, session_id, stop_event, browser_done_event))
    exit_to_browser = asyncio.create_task(tunnel_exit_to_browser(writer, session_id, stop_event, browser_done_event))

    try:
        await stop_event.wait()
        log_debug("CLIENT", "Tunnel stopping", session=session_id)
        await asyncio.sleep(TUNNEL_POST_CLOSE_GRACE_SECONDS)
    finally:
        for task in (browser_to_exit, exit_to_browser):
            if not task.done():
                task.cancel()
        await asyncio.gather(browser_to_exit, exit_to_browser, return_exceptions=True)

        RUNTIME.unregister_session_stop_event(session_id)

        try:
            close_response = await send_tunnel_close(session_id)
            log_debug("CLIENT", f"Tunnel close response: {close_response}", session=session_id)
        except Exception as exc:
            log_error("CLIENT", f"Tunnel close request failed: {exc}", session=session_id)

        session = RUNTIME.sessions.get(session_id)
        if session and session.status not in {"error"}:
            RUNTIME.mark_session_closed(session_id)

        session = RUNTIME.sessions.get(session_id)
        browser_total = session.bytes_from_browser if session else 0
        return_total = session.bytes_to_browser if session else 0
        duration = ((session.closed_at or time.time()) - session.started_at) if session else 0
        log_info("CLIENT", f"Session closed | up={human_bytes(browser_total)} | down={human_bytes(return_total)} | duration={human_duration(duration)}", session=session_id)
        session_circuit = session.circuit if session else RUNTIME.get_session_circuit(session_id)
        log_info(
            "CLIENT",
            reverse_route(session_circuit, destination),
            session=session_id,
        )


async def handle_http_via_tunnel(writer, raw_request: bytes, body: bytes = b"") -> None:
    """Plain HTTP path that piggybacks on the CONNECT tunnel mechanism.

    Used when padding is enabled. The default exit_request action returns
    the entire HTTP response in a single round trip, which does not fit in
    one fixed-size padded onion cell once a response gets bigger than a
    few KB. Tunnels already chunk reads (one chunk per padded poll), so
    routing plain HTTP through the same machinery makes padding mode work
    for HTTP responses of any size, with the same per-cell privacy
    properties as HTTPS browsing.
    """
    session_id = uuid.uuid4().hex
    dest_host, dest_port, rebuilt_request, _method, path = parse_http_proxy_request(raw_request, body=body)
    destination = f"{dest_host}:{dest_port}"

    request_circuit = RUNTIME.current_circuit
    if request_circuit is None:
        msg = (
            "Onion network has no active circuit yet (directory not populated). "
            "Check the popup's 'Directory not live' banner for the specific reason."
        )
        log_error("CLIENT", msg, session=session_id)
        body_bytes = msg.encode("utf-8")
        writer.write(
            b"HTTP/1.1 503 Service Unavailable\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Length: " + str(len(body_bytes)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body_bytes
        )
        await writer.drain()
        return

    RUNTIME.create_session(session_id, "http", destination, circuit=request_circuit)

    log_info("CLIENT", f"Requested path = {path} (padded HTTP via tunnel)", session=session_id)
    log_info("CLIENT", f"Browser requested destination {destination}", session=session_id)
    log_info("CLIENT", forward_route(request_circuit, destination), session=session_id)

    # 1. Open tunnel to the destination.
    open_response = await send_tunnel_open(session_id, dest_host, dest_port)
    if not open_response.get("ok"):
        error_text = open_response.get("error", "tunnel_open_failed")
        log_error("CLIENT", f"Padded HTTP tunnel open failed: {error_text}", session=session_id)
        RUNTIME.mark_session_error(session_id, error_text)
        try:
            from shared.security import request_directory_refresh
            request_directory_refresh()
        except Exception:
            pass
        if RUNTIME.record_circuit_failure():
            old = RUNTIME.current_circuit.circuit_id
            new = RUNTIME.new_circuit(force_contributor_path_off=True)
            log_info(
                "CLIENT",
                f"Force-rebuilt circuit (contributor path off this time) after {RUNTIME._failure_threshold_for_rebuild} consecutive padded-HTTP failures: {old} -> {new}",
            )
        body_bytes = error_text.encode("utf-8")
        writer.write(
            b"HTTP/1.1 502 Bad Gateway\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Length: " + str(len(body_bytes)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body_bytes
        )
        await writer.drain()
        return

    RUNTIME.mark_session_open(session_id)
    RUNTIME.record_circuit_success()

    # 2. Write the rebuilt HTTP request through the tunnel in chunks no bigger
    #    than the per-cell payload limit. The tunnel writer already understands
    #    stream_data packets; we just have to feed it.
    try:
        request_total = 0
        for offset in range(0, len(rebuilt_request), MAX_STREAM_CHUNK_SIZE):
            chunk = rebuilt_request[offset:offset + MAX_STREAM_CHUNK_SIZE]
            data_response = await send_tunnel_data(session_id, chunk)
            if not data_response.get("ok"):
                raise RuntimeError(data_response.get("error", "tunnel_write_failed"))
            request_total += len(chunk)
        RUNTIME.add_browser_bytes(session_id, request_total)
        log_debug("CLIENT", f"Wrote {request_total} request bytes through padded tunnel", session=session_id)

        # 3. Poll until EOF (or error). The exit chunks reads to one
        #    STREAM_READ_SIZE-sized piece per poll under padding mode, so
        #    each round trip stays inside one padded cell.
        idle_polls = 0
        while True:
            poll_response = await send_tunnel_poll(session_id)
            if not poll_response.get("ok"):
                raise RuntimeError(poll_response.get("error", "tunnel_poll_failed"))
            data_b64 = poll_response.get("data_b64", "")
            data = b64_decode_bytes(data_b64) if data_b64 else b""
            if data:
                idle_polls = 0
                RUNTIME.add_return_bytes(session_id, len(data))
                writer.write(data)
                await writer.drain()
            if poll_response.get("eof"):
                log_debug("CLIENT", "Padded tunnel reached EOF", session=session_id)
                break
            if not data:
                idle_polls += 1
                # Once the destination has finished sending we expect EOF.
                # If we keep getting empty polls beyond a generous window,
                # bail out so the browser isn't stuck forever.
                if idle_polls > int(EXIT_HTTP_RESPONSE_TIMEOUT_SECONDS_NO_DATA / max(0.01, TUNNEL_POLL_INTERVAL)):
                    log_debug("CLIENT", "Padded tunnel idle window expired", session=session_id)
                    break
                await asyncio.sleep(TUNNEL_POLL_INTERVAL)

        log_info("CLIENT", "Padded HTTP response delivered to browser", session=session_id)
        log_info("CLIENT", reverse_route(request_circuit, destination), session=session_id)
    except Exception as exc:
        log_error("CLIENT", f"Padded HTTP tunnel error: {exc}", session=session_id)
        RUNTIME.mark_session_error(session_id, str(exc))
    finally:
        try:
            await send_tunnel_close(session_id)
        except Exception as close_exc:
            log_error("CLIENT", f"Padded HTTP tunnel close failed: {close_exc}", session=session_id)
        sess = RUNTIME.sessions.get(session_id)
        if sess and sess.status not in {"error"}:
            RUNTIME.mark_session_closed(session_id)
        sess = RUNTIME.sessions.get(session_id)
        browser_total = sess.bytes_from_browser if sess else 0
        return_total = sess.bytes_to_browser if sess else 0
        duration = ((sess.closed_at or time.time()) - sess.started_at) if sess else 0
        log_info(
            "CLIENT",
            f"Session closed | up={human_bytes(browser_total)} | down={human_bytes(return_total)} | duration={human_duration(duration)}",
            session=session_id,
        )


async def handle_http_request(writer, raw_request: bytes, body: bytes = b"") -> None:
    request_session_id = uuid.uuid4().hex
    dest_host, dest_port, rebuilt_request, _method, path = parse_http_proxy_request(raw_request, body=body)
    destination = f"{dest_host}:{dest_port}"

    request_circuit = RUNTIME.current_circuit
    if request_circuit is None:
        msg = (
            "Onion network has no active circuit yet (directory not populated). "
            "Check the popup's 'Directory not live' banner for the specific reason."
        )
        log_error("CLIENT", msg, session=request_session_id)
        body_bytes = msg.encode("utf-8")
        writer.write(
            b"HTTP/1.1 503 Service Unavailable\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Length: " + str(len(body_bytes)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body_bytes
        )
        await writer.drain()
        return
    RUNTIME.create_session(request_session_id, "http", destination, circuit=request_circuit)
    RUNTIME.mark_session_open(request_session_id)

    log_info("CLIENT", f"Requested path = {path}", session=request_session_id)
    log_info("CLIENT", f"Browser requested destination {destination}", session=request_session_id)
    log_info(
        "CLIENT",
        forward_route(request_circuit, destination),
        session=request_session_id,
    )

    onion_message, hop_keys = build_onion_http_request(dest_host, dest_port, rebuilt_request, request_circuit, padding_enabled=RUNTIME.padding_enabled, cell_size=RUNTIME.padding_cell_size)
    log_debug("CLIENT", f"Rebuilt destination request size = {len(rebuilt_request)} bytes", session=request_session_id)
    RUNTIME.add_browser_bytes(request_session_id, len(rebuilt_request))
    response = await onion_round_trip(onion_message, request_circuit, hop_keys)

    if not response.get("ok"):
        error_text = response.get("error", "Unknown relay error")
        log_error("CLIENT", f"Relay chain returned error: {error_text}", session=request_session_id)
        RUNTIME.mark_session_error(request_session_id, error_text)
        # The circuit just failed. The most common cause is that one of the
        # hops became unreachable mid-session (e.g. a contributor's machine
        # was shut down). Signal an immediate directory refresh and let the
        # auto-rotate health check rebuild the circuit before the next
        # browser request lands. We don't rebuild here synchronously
        # because we don't yet know if the next request will use this
        # session's circuit or a freshly-rotated one.
        try:
            from shared.security import request_directory_refresh
            request_directory_refresh()
        except Exception:
            pass
        if RUNTIME.record_circuit_failure():
            old = RUNTIME.current_circuit.circuit_id
            # Use force_contributor_path_off so the rebuilt circuit avoids
            # the contributor path. Once the cache has caught up and
            # contributors that are actually online are present, the next
            # scheduled rotation will re-introduce contributor path mode
            # because contributor_path_enabled is still True.
            new = RUNTIME.new_circuit(force_contributor_path_off=True)
            log_info(
                "CLIENT",
                f"Force-rebuilt circuit (contributor path off this time) after {RUNTIME._failure_threshold_for_rebuild} consecutive failures: {old} -> {new}",
            )
        error_response = (
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(error_text.encode('utf-8'))}\r\n"
            "Connection: close\r\n\r\n"
            f"{error_text}"
        ).encode("utf-8")
        writer.write(error_response)
        await writer.drain()
        log_info("CLIENT", "Sent 502 Bad Gateway back to browser", session=request_session_id)
        return

    # Successful round-trip — clear the failure counter.
    RUNTIME.record_circuit_success()

    response_bytes = b64_decode_bytes(response["response_b64"])
    RUNTIME.add_return_bytes(request_session_id, len(response_bytes))
    log_info("CLIENT", f"Response returned through onion path ({len(response_bytes)} bytes)", session=request_session_id)
    session = RUNTIME.sessions.get(request_session_id)
    session_circuit = session.circuit if session else request_circuit
    log_info(
        "CLIENT",
        reverse_route(session_circuit, destination),
        session=request_session_id,
    )

    writer.write(response_bytes)
    await writer.drain()
    log_info("CLIENT", "Sent final HTTP response back to browser successfully", session=request_session_id)

    RUNTIME.mark_session_closed(request_session_id)
    session = RUNTIME.sessions.get(request_session_id)
    browser_total = session.bytes_from_browser if session else 0
    return_total = session.bytes_to_browser if session else 0
    duration = ((session.closed_at or time.time()) - session.started_at) if session else 0
    log_info("CLIENT", f"Session closed | up={human_bytes(browser_total)} | down={human_bytes(return_total)} | duration={human_duration(duration)}", session=request_session_id)


async def handle_browser(reader, writer) -> None:
    peer = writer.get_extra_info("peername")
    log_info("CLIENT", f"Browser connected from {peer}")
    try:
        if not RUNTIME.enabled:
            global LAST_DISABLED_LOG_AT
            if time.time() - LAST_DISABLED_LOG_AT >= 2:
                log_info("CLIENT", "Proxy received request while onion routing is disabled; fail-closed response sent, no direct browsing leak")
                LAST_DISABLED_LOG_AT = time.time()
            writer.write(disabled_http_response())
            await writer.drain()
            return

        raw_request, leftover = await read_browser_request_headers(reader)
        if not raw_request:
            log_debug("CLIENT", "No request data received from browser")
            return

        log_info("CLIENT", f"Read {len(raw_request)} bytes of browser request headers")
        method, target, version, header_lines = parse_request_head(raw_request)
        log_info("CLIENT", f"HTTP method = {method}")
        log_info("CLIENT", f"Request target = {target}")
        log_debug("CLIENT", f"HTTP version = {version}")

        if method == "CONNECT":
            dest_host, dest_port, _ = parse_connect_request(raw_request)
            await handle_connect_tunnel(reader, writer, dest_host, dest_port)
            return

        # Read the request body (POST/PUT/PATCH) so it gets forwarded too.
        body = b""
        cl_header = header_value(header_lines, "Content-Length")
        te_header = header_value(header_lines, "Transfer-Encoding")
        if te_header and "chunked" in te_header.lower():
            log_error("CLIENT", "Chunked transfer-encoded request bodies are not supported")
            err = "Chunked transfer-encoding is not supported by this proxy.".encode("utf-8")
            writer.write(
                b"HTTP/1.1 411 Length Required\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                + f"Content-Length: {len(err)}\r\n".encode("utf-8")
                + b"Connection: close\r\n\r\n"
                + err
            )
            await writer.drain()
            return
        if cl_header:
            try:
                content_length = int(cl_header)
            except ValueError:
                content_length = 0
            if content_length > 0:
                body = await read_request_body(reader, leftover, content_length)
                log_info("CLIENT", f"Read {len(body)} bytes of request body")

        # When padding is enabled, plain HTTP must go through the tunnel
        # path: the existing exit_request action returns the entire HTTP
        # response in a single padded onion cell, which crashes for any
        # response over ~12 KB. The tunnel path chunks reads and stays
        # within the cell size on every round trip.
        if RUNTIME.padding_enabled:
            await handle_http_via_tunnel(writer, raw_request, body=body)
        else:
            await handle_http_request(writer, raw_request, body=body)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log_error("CLIENT", f"Local onion client error: {exc}")
        error_text = "Local onion client error"
        fallback = (
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(error_text.encode('utf-8'))}\r\n"
            "Connection: close\r\n\r\n"
            f"{error_text}"
        ).encode("utf-8")
        try:
            writer.write(fallback)
            await writer.drain()
            log_info("CLIENT", "Sent fallback 500 error response to browser")
        except Exception:
            pass
    finally:
        await safe_close_writer(writer, "CLIENT", verbose=True)
        log_debug("CLIENT", "Browser connection closed")


async def main() -> None:
    from shared.security import start_directory_refresher
    start_directory_refresher()
    control_server = await start_control_api(RUNTIME)
    proxy_server = await asyncio.start_server(handle_browser, CLIENT_PROXY_HOST, CLIENT_PROXY_PORT)
    auto_rotate_task = asyncio.create_task(auto_rotate_loop())

    log_info("CLIENT", f"Local onion proxy listening on {CLIENT_PROXY_HOST}:{CLIENT_PROXY_PORT}")
    log_info("CLIENT", "Waiting for browser connections...")
    log_info("CONTROL", f"Local control API ready at http://{RUNTIME.control_host}:{RUNTIME.control_port}")
    RUNTIME.log_state_summary("Startup state")

    async with control_server, proxy_server:
        try:
            await asyncio.gather(control_server.serve_forever(), proxy_server.serve_forever())
        finally:
            auto_rotate_task.cancel()
            await asyncio.gather(auto_rotate_task, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
