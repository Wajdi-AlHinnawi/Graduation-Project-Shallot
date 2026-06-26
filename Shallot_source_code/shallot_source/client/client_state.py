from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import asyncio
import json
import os
import time
import uuid
import random

from client.directory import DEFAULT_DIRECTORY_PATH, RelayNode, enumerate_circuits, load_directory
from shared.config import (
    CLIENT_PROXY_HOST,
    CLIENT_PROXY_PORT,
    CONTROL_HOST,
    CONTROL_PORT,
    PADDED_CELL_SIZE,
    AUTO_ROTATE_MIN_SECONDS,
    AUTO_ROTATE_JITTER_PERCENT,
    CONTRIBUTOR_MAX_HOPS,
)
from shared.logging_utils import log_info, log_error
from shared.security import get_or_create_control_token

# Persisted client settings live next to the control token so the user does
# not have to re-enter the directory server URL on every proxy_client restart.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CLIENT_SETTINGS_PATH = PROJECT_ROOT / "client_settings_dev.json"


def _load_persisted_settings() -> dict:
    if not CLIENT_SETTINGS_PATH.exists():
        return {}
    try:
        with CLIENT_SETTINGS_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            return data
    except Exception as exc:
        log_error("CLIENT", f"Could not load persisted client settings: {exc}")
    return {}


def _save_persisted_settings(data: dict) -> None:
    try:
        CLIENT_SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = CLIENT_SETTINGS_PATH.with_suffix(CLIENT_SETTINGS_PATH.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        tmp.replace(CLIENT_SETTINGS_PATH)
    except Exception as exc:
        log_error("CLIENT", f"Could not persist client settings: {exc}")


@dataclass(frozen=True)
class ContributorHop:
    relay_id: str
    host: str
    port: int
    public_key_b64: str


@dataclass(frozen=True)
class CircuitInfo:
    circuit_id: str
    entry_id: str
    middle_id: str
    exit_id: str
    entry_host: str
    entry_port: int
    middle_host: str
    middle_port: int
    exit_host: str
    exit_port: int
    entry_public_key_b64: str
    middle_public_key_b64: str
    exit_public_key_b64: str
    contributors: tuple[ContributorHop, ...] = tuple()
    created_at: float = field(default_factory=time.time)

    @property
    def has_contributor(self) -> bool:
        return bool(self.contributors)

    @property
    def contributor_id(self) -> Optional[str]:
        return self.contributors[0].relay_id if self.contributors else None

    @property
    def contributor_host(self) -> Optional[str]:
        return self.contributors[0].host if self.contributors else None

    @property
    def contributor_port(self) -> Optional[int]:
        return self.contributors[0].port if self.contributors else None

    @property
    def contributor_public_key_b64(self) -> str:
        return self.contributors[0].public_key_b64 if self.contributors else ""

    @property
    def contributor_ids(self) -> list[str]:
        return [hop.relay_id for hop in self.contributors]

    @property
    def route_summary(self) -> str:
        parts = [f"{self.entry_id}:{self.entry_port}", f"{self.middle_id}:{self.middle_port}"]
        parts.extend(f"{hop.relay_id}:{hop.port}" for hop in self.contributors)
        parts.append(f"{self.exit_id}:{self.exit_port}")
        return " -> ".join(parts)


@dataclass
class SessionInfo:
    session_id: str
    session_type: str
    destination: str
    status: str
    circuit: CircuitInfo
    started_at: float = field(default_factory=time.time)
    closed_at: Optional[float] = None
    bytes_from_browser: int = 0
    bytes_to_browser: int = 0
    last_error: Optional[str] = None


class ClientRuntimeState:
    def __init__(self) -> None:
        # Resolve the directory server URL BEFORE anything else, so the URL
        # is in os.environ before the background refresher thread makes its
        # first fetch. Resolution priority is implemented in
        # shared.security.get_directory_server_url:
        #   1. SP_DIRECTORY_SERVER_URL env var (operator override)
        #   2. directory_config.json (created by tools/install_client.py)
        #   3. directory_server_url.txt (auto-written by the directory
        #      server itself when running on the same machine, or set by
        #      operator workflows)
        #   4. Auto-detect: directory_signing_key.json present means this
        #      machine IS the directory server, so URL = http://localhost:7071
        # We also restore from client_settings_dev.json for backwards compat.
        persisted = _load_persisted_settings()
        url = str(persisted.get("directory_server_url") or "").strip().rstrip("/")
        url_source = "client_settings_dev.json" if url else None
        if not url:
            try:
                from shared.security import get_directory_server_url
                url = get_directory_server_url()
                if url:
                    if os.getenv("SP_DIRECTORY_SERVER_URL", "").strip().rstrip("/") == url:
                        url_source = "SP_DIRECTORY_SERVER_URL env var"
                    elif (PROJECT_ROOT / "directory_config.json").exists():
                        url_source = "directory_config.json"
                    elif (PROJECT_ROOT / "directory_server_url.txt").exists():
                        url_source = "directory_server_url.txt"
                    elif (PROJECT_ROOT / "directory_signing_key.json").exists():
                        url_source = "auto-detected (this machine is the directory server)"
                    else:
                        url_source = "unknown source"
            except Exception:
                url = ""
        if url:
            os.environ.setdefault("SP_DIRECTORY_SERVER_URL", url)
            log_info("CLIENT", f"Directory server URL: {url} (source: {url_source})")
        else:
            log_info("CLIENT", "No directory server URL configured. On the directory-server machine, this is set automatically when you start run_directory_server.py. On other machines, run tools/install_client.py http://<directory-server>:7071 to bake one in.")

        self.enabled = True
        self.proxy_host = CLIENT_PROXY_HOST
        self.proxy_port = CLIENT_PROXY_PORT
        self.control_host = CONTROL_HOST
        self.control_port = CONTROL_PORT
        self.control_token = get_or_create_control_token()
        self.directory_path = DEFAULT_DIRECTORY_PATH
        self.directory_server_url = url

        # Kick off the background directory refresher BEFORE we try to read
        # the directory, then briefly wait for the first fetch to complete.
        # On an end-user laptop install there is no local directory.json
        # (that's intentional — relay topology must come from the live
        # signed directory), so an immediate read would yield an empty
        # list and circuit selection would fail.
        try:
            from shared.security import (
                start_directory_refresher,
                directory_cache_status,
                request_directory_refresh,
            )
            start_directory_refresher()
            request_directory_refresh()
            # Up to 3s, polled every 100ms. Most of the time the first
            # fetch completes in tens of ms; this generous deadline
            # tolerates the directory server being briefly slow without
            # making startup feel sluggish.
            deadline = time.time() + 3.0
            while time.time() < deadline:
                status = directory_cache_status()
                if status.get("source") == "directory_server":
                    break
                time.sleep(0.1)
        except Exception as exc:
            log_error("CLIENT", f"Could not start directory refresher: {exc}")

        self.directory_relays: list[RelayNode] = load_directory(self.directory_path)
        self.selected_entry_id: Optional[str] = None

        # This device donating itself as a contributor middle relay.
        self.contributor_mode_enabled = False
        self.local_contributor_id: Optional[str] = None

        # This device browsing through other contributor middle relays.
        self.contributor_path_enabled = False
        self.contributor_path_hops = 1

        self.padding_enabled = False
        self.padding_cell_size = PADDED_CELL_SIZE
        self._route_cycle_index = 0
        self._route_cycle_seed: tuple | None = None

        # Try to build the initial circuit; if the directory is still empty
        # (e.g. directory server unreachable at startup), defer the first
        # circuit so the process can still start and the popup/dashboard
        # can show "Directory not live" with a useful error. The auto-rotate
        # loop and per-request paths will rebuild as soon as the cache
        # populates.
        self.current_circuit: CircuitInfo | None = None
        try:
            self.current_circuit = self._build_circuit()
        except ValueError as exc:
            log_error(
                "CLIENT",
                f"Cannot build initial circuit yet: {exc}. "
                f"This usually means the directory server is unreachable. "
                f"Browsing will fail until the directory cache populates; "
                f"the popup will show 'Directory not live' with details. "
                f"Run tools/install_client.py http://<directory-server>:7071 if you have not configured a directory server URL.",
            )
        self.previous_circuit_id = None
        self.sessions: dict[str, SessionInfo] = {}
        self._active_session_stop_events: dict[str, asyncio.Event] = {}
        self.max_recent_closed_sessions = 120
        self.total_sessions_opened = 0
        self.total_bytes_from_browser = 0
        self.total_bytes_to_browser = 0
        self.started_at = time.time()
        self.auto_rotate_enabled = True
        self.auto_rotate_interval_seconds = AUTO_ROTATE_MIN_SECONDS
        self.next_rotation_at = self._next_rotation_deadline()
        # Counts consecutive relay-chain failures on the current circuit so
        # we can force a rebuild when the circuit clearly isn't working,
        # even if the directory cache still believes every relay is online
        # (e.g. during the 0-60s window before missed heartbeats are
        # detected by the directory server).
        self._consecutive_circuit_failures = 0
        self._failure_threshold_for_rebuild = 3

    def record_circuit_failure(self) -> bool:
        """Increment the failure counter; return True iff the circuit should
        be rebuilt right now (caller is expected to call new_circuit)."""
        self._consecutive_circuit_failures += 1
        if self._consecutive_circuit_failures >= self._failure_threshold_for_rebuild:
            self._consecutive_circuit_failures = 0
            return True
        return False

    def record_circuit_success(self) -> None:
        """Reset the failure counter after a successful round-trip."""
        if self._consecutive_circuit_failures != 0:
            self._consecutive_circuit_failures = 0

    def _new_circuit_id(self) -> str:
        return uuid.uuid4().hex

    def _route_signature(self, candidate) -> tuple[str, ...]:
        entry, middle, contributors, exit_node = candidate
        return (entry.relay_id, middle.relay_id, *(c.relay_id for c in contributors), exit_node.relay_id)

    def _pick_route(self, previous_route: tuple[str, ...] | None = None, *, force_contributor_path_off: bool = False):
        exclude = {self.local_contributor_id} if self.local_contributor_id else set()
        contributor_path_enabled = self.contributor_path_enabled and not force_contributor_path_off
        candidates = enumerate_circuits(
            self.directory_relays,
            preferred_entry_id=self.selected_entry_id,
            contributor_path_enabled=contributor_path_enabled,
            contributor_hops=self.contributor_path_hops,
            exclude_contributor_ids=exclude,
        )
        signature = (
            self.selected_entry_id,
            contributor_path_enabled,
            self.contributor_path_hops,
            tuple(sorted(r.relay_id for r in self.directory_relays if r.role == "entry" and r.online)),
            tuple(sorted(r.relay_id for r in self.directory_relays if r.role == "middle" and r.online and r.official and not r.contributor)),
            tuple(sorted(r.relay_id for r in self.directory_relays if r.role == "middle" and r.online and r.contributor)),
            tuple(sorted(r.relay_id for r in self.directory_relays if r.role == "exit" and r.online)),
        )
        if signature != self._route_cycle_seed:
            self._route_cycle_seed = signature
            self._route_cycle_index = 0
        ordered = sorted(candidates, key=self._route_signature)
        if previous_route is not None and len(ordered) > 1:
            filtered = [candidate for candidate in ordered if self._route_signature(candidate) != previous_route]
            if filtered:
                ordered = filtered
        pick = ordered[self._route_cycle_index % len(ordered)]
        self._route_cycle_index += 1
        return pick

    def _build_circuit(self, previous_route: tuple[str, ...] | None = None, *, force_contributor_path_off: bool = False) -> CircuitInfo:
        entry, middle, contributors, exit_node = self._pick_route(
            previous_route=previous_route, force_contributor_path_off=force_contributor_path_off,
        )
        contributor_hops = tuple(
            ContributorHop(
                relay_id=node.relay_id,
                host=node.host,
                port=node.port,
                public_key_b64=node.public_key_b64,
            )
            for node in contributors
        )
        return CircuitInfo(
            circuit_id=self._new_circuit_id(),
            entry_id=entry.relay_id,
            middle_id=middle.relay_id,
            exit_id=exit_node.relay_id,
            entry_host=entry.host,
            entry_port=entry.port,
            middle_host=middle.host,
            middle_port=middle.port,
            exit_host=exit_node.host,
            exit_port=exit_node.port,
            entry_public_key_b64=entry.public_key_b64,
            middle_public_key_b64=middle.public_key_b64,
            exit_public_key_b64=exit_node.public_key_b64,
            contributors=contributor_hops,
        )

    def reload_directory(self) -> None:
        # Signal the background refresher to re-fetch from the directory
        # server soon. The cached value is used immediately; the refresher
        # will update it within a few hundred milliseconds.
        try:
            from shared.security import request_directory_refresh
            request_directory_refresh()
        except Exception:
            pass
        self.directory_relays = load_directory(self.directory_path)

    def _next_rotation_deadline(self) -> float:
        jitter = self.auto_rotate_interval_seconds * AUTO_ROTATE_JITTER_PERCENT
        return time.time() + self.auto_rotate_interval_seconds + random.uniform(-jitter, jitter)

    def _reset_rotation_deadline(self) -> None:
        self.next_rotation_at = self._next_rotation_deadline()

    def new_circuit(self, *, force_contributor_path_off: bool = False) -> str:
        """Build a fresh circuit. If `force_contributor_path_off` is True,
        we ignore the user's contributor_path_enabled preference for this
        one circuit and build the official path instead. This is used as
        a fallback when consecutive failures suggest the chosen contributor
        is dead but the directory cache hasn't caught up yet — falling back
        to the official path keeps browsing working until the cache
        refreshes and the next regular rotation can re-introduce contributor
        path mode if appropriate.
        """
        self.reload_directory()
        previous = getattr(self, "current_circuit", None)
        previous_route = None
        if previous is not None:
            previous_route = tuple(part.split(":", 1)[0] for part in previous.route_summary.split(" -> "))
        self.current_circuit = self._build_circuit(
            previous_route=previous_route,
            force_contributor_path_off=force_contributor_path_off,
        )
        self.previous_circuit_id = previous.circuit_id if previous else None
        self._reset_rotation_deadline()
        return self.current_circuit.circuit_id

    def is_current_circuit_healthy(self) -> tuple[bool, str | None]:
        """Return (True, None) if every relay in the current circuit is still
        present and online in the directory cache. Otherwise return
        (False, reason) so the caller can decide to rebuild the circuit.
        """
        circuit = getattr(self, "current_circuit", None)
        if circuit is None:
            return True, None
        # Build a quick lookup from the latest cached directory.
        try:
            self._refresh_directory_relays_from_cache()
        except Exception:
            pass
        by_id = {r.relay_id: r for r in self.directory_relays}
        circuit_ids: list[str] = [circuit.entry_id, circuit.middle_id]
        circuit_ids.extend(c.relay_id for c in circuit.contributors)
        circuit_ids.append(circuit.exit_id)
        for relay_id in circuit_ids:
            relay = by_id.get(relay_id)
            if relay is None:
                return False, f"relay {relay_id} no longer in directory"
            if not relay.online:
                return False, f"relay {relay_id} is offline (status={relay.status}, enabled={relay.enabled})"
        return True, None

    def set_entry_preference(self, entry_id: str, rebuild: bool = True) -> str | None:
        self.selected_entry_id = entry_id or None
        if rebuild:
            return self.new_circuit()
        return None

    def set_auto_rotate(self, enabled: bool, interval_seconds: int | None = None) -> None:
        self.auto_rotate_enabled = bool(enabled)
        if interval_seconds is not None:
            self.auto_rotate_interval_seconds = max(AUTO_ROTATE_MIN_SECONDS, int(interval_seconds))
        self._reset_rotation_deadline()

    def set_directory_server_url(self, url: str) -> dict:
        """Persist the directory server URL and signal an immediate refresh.

        This is used by the popup to keep the URL across proxy_client
        restarts, so the user does not have to re-enter it. Also updates
        os.environ so the background refresher picks it up on the next cycle.

        We persist the URL into TWO files:
          * client_settings_dev.json — read by ClientRuntimeState on startup
            so the proxy_client process picks it up.
          * directory_server_url.txt — read by shared.security.get_directory_server_url
            on every refresher cycle. This file is what every other process
            (entry/middle/exit relay, contributor relay) reads to find the
            directory server. Writing to it here means a single popup
            interaction propagates the URL to all relay processes that
            share this project root, so each of them can fetch the live
            directory and validate next-hops correctly.
        """
        clean = (url or "").strip().rstrip("/")
        previous = self.directory_server_url
        self.directory_server_url = clean

        # Persist via the shared canonical location AND in os.environ, so
        # both the client and any relay processes started from the same
        # project root see the new URL.
        try:
            from shared.security import set_directory_server_url as _persist_url
            _persist_url(clean)
        except Exception:
            # Fall back to env-only update if the helper isn't available.
            if clean:
                os.environ["SP_DIRECTORY_SERVER_URL"] = clean
            else:
                os.environ.pop("SP_DIRECTORY_SERVER_URL", None)

        # Also persist into client_settings_dev.json so the proxy_client
        # ClientRuntimeState init path restores it on next startup.
        persisted = _load_persisted_settings()
        persisted["directory_server_url"] = clean
        _save_persisted_settings(persisted)

        # Trigger an immediate background refresh so the cache picks up the
        # new URL within ~100 ms instead of waiting up to TTL seconds.
        try:
            from shared.security import request_directory_refresh
            request_directory_refresh()
        except Exception:
            pass

        if clean != previous:
            log_info("CLIENT", f"Directory server URL set to: {clean or '(none)'}")
        return {"ok": True, "directory_server_url": clean, "previous": previous}

    def set_contributor_mode(self, enabled: bool, contributor_id: str | None = None) -> None:
        self.contributor_mode_enabled = bool(enabled)
        self.local_contributor_id = contributor_id if enabled else None
        # The user just toggled contributor donation; ask the cache to
        # re-pull the directory so other clients see this change quickly.
        try:
            from shared.security import request_directory_refresh
            request_directory_refresh()
        except Exception:
            pass

    def set_contributor_path(self, enabled: bool, hops: int | None = None) -> str:
        self.contributor_path_enabled = bool(enabled)
        if hops is not None:
            self.contributor_path_hops = max(1, min(CONTRIBUTOR_MAX_HOPS, int(hops)))
        # When the user enables Contributor Path mode, refresh the directory
        # immediately so we pick up freshly registered contributors instead
        # of waiting up to TTL seconds for the next scheduled refresh.
        try:
            from shared.security import request_directory_refresh
            request_directory_refresh()
        except Exception:
            pass
        return self.new_circuit()

    def set_padding_mode(self, enabled: bool, cell_size: int | None = None) -> None:
        self.padding_enabled = bool(enabled)
        if cell_size is not None:
            self.padding_cell_size = max(4096, int(cell_size))

    def format_current_route(self) -> str:
        c = self.current_circuit
        if c is None:
            return "no active circuit"
        parts = ["CLIENT", f"ENTRY({c.entry_id}:{c.entry_port})", f"MIDDLE({c.middle_id}:{c.middle_port})"]
        for i, hop in enumerate(c.contributors, start=1):
            parts.append(f"CONTRIBUTOR{i}({hop.relay_id}:{hop.port})")
        parts.append(f"EXIT({c.exit_id}:{c.exit_port})")
        return " -> ".join(parts)

    def format_security_mode(self) -> str:
        padding = f"padding=ON fixed_cell={self.padding_cell_size}B" if self.padding_enabled else "padding=OFF variable-size"
        rotation = f"auto-rotate=ON every {self.auto_rotate_interval_seconds}s" if self.auto_rotate_enabled else "auto-rotate=OFF manual"
        preferred = self.selected_entry_id if self.selected_entry_id else "any"
        contributor = "ON" if self.contributor_mode_enabled else "OFF"
        contrib_path = f"ON hops={self.contributor_path_hops}" if self.contributor_path_enabled else "OFF"
        routing = "enabled" if self.enabled else "disabled/fail-closed"
        return f"routing={routing} | {padding} | {rotation} | preferred-entry={preferred} | contribute={contributor} | contributor-path={contrib_path}"

    def log_state_summary(self, action: str) -> None:
        log_info("CONTROL", f"{action} | {self.format_security_mode()}")
        if self.current_circuit is not None:
            log_info("CONTROL", f"Active circuit {self.current_circuit.circuit_id}: {self.format_current_route()}")
        else:
            log_info("CONTROL", "No active circuit (directory not yet available)")
        log_info("CONTROL", "Policy: existing open sessions keep their original circuit; new sessions use the active circuit.")

    def seconds_until_rotation(self) -> int:
        if not self.auto_rotate_enabled:
            return -1
        return max(0, int(self.next_rotation_at - time.time()))

    def _prune_closed_sessions(self) -> None:
        closed_ids = [item.session_id for item in sorted(self.sessions.values(), key=lambda s: s.closed_at or 0.0, reverse=True) if item.status in {"closed", "error"}]
        for stale_id in closed_ids[self.max_recent_closed_sessions:]:
            self.sessions.pop(stale_id, None)

    def create_session(self, session_id: str, session_type: str, destination: str, circuit: CircuitInfo | None = None) -> None:
        self._prune_closed_sessions()
        self.sessions[session_id] = SessionInfo(session_id=session_id, session_type=session_type, destination=destination, status="opening", circuit=circuit or self.current_circuit)
        self.total_sessions_opened += 1

    def get_session_circuit(self, session_id: str) -> CircuitInfo:
        session = self.sessions.get(session_id)
        if session is not None:
            return session.circuit
        return self.current_circuit

    def mark_session_open(self, session_id: str) -> None:
        if session_id in self.sessions:
            self.sessions[session_id].status = "open"

    def mark_session_closed(self, session_id: str) -> None:
        if session_id in self.sessions:
            self.sessions[session_id].status = "closed"
            self.sessions[session_id].closed_at = time.time()
            self._prune_closed_sessions()

    def mark_session_error(self, session_id: str, error: str) -> None:
        if session_id in self.sessions:
            self.sessions[session_id].status = "error"
            self.sessions[session_id].last_error = error
            self.sessions[session_id].closed_at = time.time()
            self._prune_closed_sessions()

    def add_browser_bytes(self, session_id: str, count: int) -> None:
        self.total_bytes_from_browser += count
        if session_id in self.sessions:
            self.sessions[session_id].bytes_from_browser += count

    def add_return_bytes(self, session_id: str, count: int) -> None:
        self.total_bytes_to_browser += count
        if session_id in self.sessions:
            self.sessions[session_id].bytes_to_browser += count

    def register_session_stop_event(self, session_id: str, stop_event: asyncio.Event) -> None:
        """Track an active CONNECT tunnel so the UI can close it on demand."""
        self._active_session_stop_events[session_id] = stop_event

    def unregister_session_stop_event(self, session_id: str) -> None:
        self._active_session_stop_events.pop(session_id, None)

    def close_active_session_tunnels(self) -> int:
        """Request active CONNECT tunnels to stop and close cleanly."""
        requested = 0
        for stop_event in list(self._active_session_stop_events.values()):
            if not stop_event.is_set():
                stop_event.set()
                requested += 1
        return requested

    def reset_sessions(self, close_active: bool = True) -> dict:
        """Close active CONNECT tunnels and clear the local dashboard session history.

        This is used by the extension's session reset button. Existing CONNECT
        tunnels are asked to stop, which triggers tunnel_close packets through the
        onion route. Then the local dashboard counters/history are cleared.
        """
        active_before = self.active_session_count()
        close_requested = self.close_active_session_tunnels() if close_active else 0
        cleared = len(self.sessions)
        self.sessions.clear()
        self.total_sessions_opened = 0
        self.total_bytes_from_browser = 0
        self.total_bytes_to_browser = 0
        return {
            "cleared_sessions": cleared,
            "active_sessions_before_reset": active_before,
            "close_requested": close_requested,
        }

    def active_session_count(self) -> int:
        return sum(1 for s in self.sessions.values() if s.status in {"opening", "open"})

    def _route_array(self, circuit: CircuitInfo | None = None) -> list[str]:
        c = circuit or self.current_circuit
        route = [
            "CLIENT",
            f"ENTRY:{c.entry_id}:{c.entry_host}:{c.entry_port}",
            f"MIDDLE:{c.middle_id}:{c.middle_host}:{c.middle_port}",
        ]
        route.extend(f"CONTRIBUTOR:{hop.relay_id}:{hop.host}:{hop.port}" for hop in c.contributors)
        route.append(f"EXIT:{c.exit_id}:{c.exit_host}:{c.exit_port}")
        return route

    def _session_route_array(self, circuit: CircuitInfo) -> list[str]:
        route = [
            f"ENTRY:{circuit.entry_id}:{circuit.entry_port}",
            f"MIDDLE:{circuit.middle_id}:{circuit.middle_port}",
        ]
        route.extend(f"CONTRIBUTOR:{hop.relay_id}:{hop.port}" for hop in circuit.contributors)
        route.append(f"EXIT:{circuit.exit_id}:{circuit.exit_port}")
        return route

    def get_status(self) -> dict:
        c = self.current_circuit
        common = {
            "ok": True,
            "enabled": self.enabled,
            "proxy_host": self.proxy_host,
            "proxy_port": self.proxy_port,
            "control_host": self.control_host,
            "control_port": self.control_port,
            "selected_entry_id": self.selected_entry_id,
            "contributor_mode_enabled": self.contributor_mode_enabled,
            "contributor_path_enabled": self.contributor_path_enabled,
            "contributor_path_hops": self.contributor_path_hops,
            "padding_enabled": self.padding_enabled,
            "padding_cell_size": self.padding_cell_size,
            "local_contributor_id": self.local_contributor_id,
            "active_sessions": self.active_session_count(),
            "total_sessions_opened": self.total_sessions_opened,
            "total_bytes_from_browser": self.total_bytes_from_browser,
            "total_bytes_to_browser": self.total_bytes_to_browser,
            "uptime_seconds": int(time.time() - self.started_at),
        }
        if c is None:
            return {
                **common,
                "circuit_id": None,
                "entry": None, "middle": None, "exit": None,
                "contributors": [],
                "circuit_status": "no_circuit_directory_unavailable",
            }
        return {
            **common,
            "circuit_id": c.circuit_id,
            "entry": f"{c.entry_host}:{c.entry_port}",
            "middle": f"{c.middle_host}:{c.middle_port}",
            "exit": f"{c.exit_host}:{c.exit_port}",
            "contributors": [{"id": h.relay_id, "host": h.host, "port": h.port} for h in c.contributors],
        }

    def get_route(self) -> dict:
        c = self.current_circuit
        if c is None:
            return {
                "circuit_id": None,
                "created_at": None,
                "selected_entry_id": self.selected_entry_id,
                "route": [],
                "contributor_count": 0,
                "contributor_ids": [],
            }
        return {
            "circuit_id": c.circuit_id,
            "created_at": c.created_at,
            "selected_entry_id": self.selected_entry_id,
            "route": self._route_array(c),
            "contributor_count": len(c.contributors),
            "contributor_ids": c.contributor_ids,
        }

    def get_sessions(self) -> dict:
        sessions_sorted = sorted(self.sessions.values(), key=lambda s: s.started_at, reverse=True)
        return {"sessions": [{
            "session_id": s.session_id,
            "type": s.session_type,
            "destination": s.destination,
            "status": s.status,
            "started_at": s.started_at,
            "closed_at": s.closed_at,
            "bytes_from_browser": s.bytes_from_browser,
            "bytes_to_browser": s.bytes_to_browser,
            "last_error": s.last_error,
            "circuit_id": s.circuit.circuit_id,
            "route": self._session_route_array(s.circuit),
        } for s in sessions_sorted]}

    def get_stats(self) -> dict:
        return {
            "total_sessions_opened": self.total_sessions_opened,
            "active_sessions": self.active_session_count(),
            "total_bytes_from_browser": self.total_bytes_from_browser,
            "total_bytes_to_browser": self.total_bytes_to_browser,
            "uptime_seconds": int(time.time() - self.started_at),
        }

    def _refresh_directory_relays_from_cache(self) -> None:
        """Lightweight in-memory refresh from the cached signed directory.

        Called on every dashboard read so that a contributor that registers
        between circuit-rebuild events still becomes visible to the popup
        promptly. The actual cache is in shared.security and is updated by
        the background refresher thread; this method just re-parses it.
        """
        try:
            self.directory_relays = load_directory(self.directory_path)
        except Exception:
            pass

    def get_directory(self) -> dict:
        # Refresh from the in-memory directory cache so the popup sees newly
        # registered contributors without waiting for a circuit rebuild.
        self._refresh_directory_relays_from_cache()
        entries = []
        middles = []
        exits = []
        contributors = []
        for relay in self.directory_relays:
            item = {
                "id": relay.relay_id,
                "role": relay.role,
                "host": relay.host,
                "port": relay.port,
                "enabled": relay.enabled,
                "label": relay.label,
                "contributor": relay.contributor,
                "official": relay.official,
                "status": relay.status,
                "last_seen": relay.last_seen,
            }
            if relay.role == "entry":
                entries.append(item)
            elif relay.role == "middle":
                middles.append(item)
                if relay.contributor:
                    contributors.append(item)
            elif relay.role == "exit":
                exits.append(item)
        online_contributors = [item for item in contributors if item.get("enabled") and item.get("status") != "offline"]
        return {
            "entries": entries,
            "middles": middles,
            "exits": exits,
            "contributors": contributors,
            "online_contributors": online_contributors,
            "online_contributor_count": len(online_contributors),
            "selected_entry_id": self.selected_entry_id,
        }

    def get_dashboard(self) -> dict:
        # Refresh in-memory directory state from the cache before rendering.
        # The cache itself is updated by the background refresher thread, so
        # this is a cheap dict-to-RelayNode reparse, not a network call.
        self._refresh_directory_relays_from_cache()
        current = self.current_circuit
        entries = [r for r in self.directory_relays if r.role == "entry"]
        middles = [r for r in self.directory_relays if r.role == "middle"]
        exits = [r for r in self.directory_relays if r.role == "exit"]
        active_contributor_ids = set(current.contributor_ids) if current is not None else set()
        active_entry = current.entry_id if current is not None else None
        active_middle = current.middle_id if current is not None else None
        active_exit = current.exit_id if current is not None else None
        relay_health = {
            "entries": [{**{"id": r.relay_id, "label": r.label, "host": r.host, "port": r.port, "enabled": r.enabled, "contributor": r.contributor, "official": r.official, "status": r.status}, "active": active_entry == r.relay_id} for r in entries],
            "middles": [{**{"id": r.relay_id, "label": r.label, "host": r.host, "port": r.port, "enabled": r.enabled, "contributor": r.contributor, "official": r.official, "status": r.status}, "active": active_middle == r.relay_id or r.relay_id in active_contributor_ids} for r in middles],
            "exits": [{**{"id": r.relay_id, "label": r.label, "host": r.host, "port": r.port, "enabled": r.enabled, "contributor": r.contributor, "official": r.official, "status": r.status}, "active": active_exit == r.relay_id} for r in exits],
        }
        directory = self.get_directory()
        # Surface directory cache health so the popup can warn the user when
        # we're falling back to a stale local file (e.g. the server is
        # unreachable, or the pinned signing key doesn't match).
        try:
            from shared.security import directory_cache_status
            cache_health = directory_cache_status()
        except Exception:
            cache_health = None
        if current is not None:
            current_contributor_count = len(current.contributors)
            route_mode = "Contributor Path" if self.contributor_path_enabled and current.contributors else "Official Path"
            current_route_label = current.route_summary
        else:
            current_contributor_count = 0
            route_mode = "No active circuit"
            current_route_label = "(no active circuit; directory not yet populated)"
        return {
            "status": self.get_status(),
            "route": self.get_route(),
            "stats": self.get_stats(),
            "sessions": self.get_sessions()["sessions"],
            "directory": directory,
            "directory_cache": cache_health,
            "relay_health": relay_health,
            "ui": {
                "current_route_label": current_route_label,
                "previous_circuit_id": self.previous_circuit_id,
                "rotation_mode": "automatic" if self.auto_rotate_enabled else "manual",
                "routing_policy": "Existing sessions stay on their original circuit. New sessions use the latest circuit.",
                "route_mode": route_mode,
            },
            "security": {
                "key_exchange": "X25519-HKDF-SHA256 per relay layer",
                "onion_padding": (f"Optional fixed-size transport cells ({self.padding_cell_size} bytes)" if self.padding_enabled else "Off - variable-size encrypted onion messages"),
                "padding_enabled": self.padding_enabled,
                "padding_cell_size": self.padding_cell_size,
                "padding_note": "When enabled, every relay-to-relay JSON frame is padded to the same size. Browser-to-proxy and exit-to-website traffic stays normal TCP/TLS.",
                "contributor_mode_enabled": self.contributor_mode_enabled,
                "contributor_mode_note": "Contribute mode runs this device as a middle-only contributor relay for other users.",
                "local_contributor_id": self.local_contributor_id,
                "contributor_path_enabled": self.contributor_path_enabled,
                "contributor_path_hops": self.contributor_path_hops,
                "contributor_path_note": "Contributor Path is optional high-anonymity mode: entry -> official middle -> contributor(s) -> exit. More contributors increase latency and failure risk.",
                "current_contributor_count": current_contributor_count,
                "online_contributor_count": directory["online_contributor_count"],
                "directory_server_url": self.directory_server_url,
            },
            "auto_rotate": {
                "enabled": self.auto_rotate_enabled,
                "interval_seconds": self.auto_rotate_interval_seconds,
                "seconds_until_rotation": self.seconds_until_rotation(),
                "next_rotation_at": self.next_rotation_at if self.auto_rotate_enabled else None,
            },
        }
