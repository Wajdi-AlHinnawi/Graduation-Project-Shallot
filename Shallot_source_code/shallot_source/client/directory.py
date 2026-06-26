"""Directory loading and dynamic circuit selection helpers.

Official path:
    ENTRY -> OFFICIAL MIDDLE -> EXIT

Contributor path mode:
    ENTRY -> OFFICIAL MIDDLE -> CONTRIBUTOR(S) -> EXIT

Contributor relays are middle-only and are never selected as entry or exit.
"""
from __future__ import annotations

import itertools
import json
import os
import random
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from shared.config import CONTRIBUTOR_MAX_HOPS
from shared.security import load_directory_payload as _load_signed_payload


@dataclass(frozen=True)
class RelayNode:
    relay_id: str
    role: str
    host: str
    port: int
    enabled: bool = True
    public_key_b64: str = ""
    contributor: bool = False
    official: bool = True
    status: str = "online"
    last_seen: float | None = None

    @property
    def online(self) -> bool:
        return self.enabled and self.status != "offline"

    @property
    def label(self) -> str:
        tag = "contributor" if self.contributor else "official"
        status = f", {self.status}" if self.contributor else ""
        return f"{self.relay_id} ({self.host}:{self.port}, {tag}{status})"


DEFAULT_DIRECTORY_PATH = Path(__file__).resolve().parent.parent / "directory.json"


def _directory_server_url() -> str:
    return os.getenv("SP_DIRECTORY_SERVER_URL", "").strip().rstrip("/")


def _load_payload(directory_path: Path) -> dict:
    """Use the shared cached + signature-verifying loader so circuit selection
    sees exactly the same directory the relays use for next-hop validation."""
    try:
        return _load_signed_payload()
    except Exception:
        # Last-resort fallback to the bundled local directory.json.
        with directory_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)


def load_directory(directory_path: Path | None = None) -> list[RelayNode]:
    path = directory_path or DEFAULT_DIRECTORY_PATH
    payload = _load_payload(path)
    relays: list[RelayNode] = []
    for item in payload.get("relays", []):
        # Topology spec entries (operator-declared official relays that have
        # not yet registered themselves) may have no host or public_key
        # filled in. Skip those — circuit selection should treat them as
        # offline until the relay process registers and supplies its host
        # and keys via /register-relay.
        host = item.get("host")
        public_key = item.get("public_key_b64")
        if not host or not public_key:
            continue
        contributor = bool(item.get("contributor", False))
        official = bool(item.get("official", not contributor))
        status = str(item.get("status", "online" if item.get("enabled", True) else "offline"))
        relays.append(RelayNode(
            relay_id=item["id"],
            role=item["role"],
            host=host,
            port=int(item["port"]),
            enabled=bool(item.get("enabled", True)),
            public_key_b64=public_key,
            contributor=contributor,
            official=official,
            status=status,
            last_seen=item.get("last_seen"),
        ))
    return relays


def relays_by_role(relays: Iterable[RelayNode], role: str) -> list[RelayNode]:
    return [relay for relay in relays if relay.online and relay.role == role]


def official_relays_by_role(relays: Iterable[RelayNode], role: str) -> list[RelayNode]:
    return [relay for relay in relays if relay.online and relay.role == role and relay.official and not relay.contributor]


def contributor_middles(relays: Iterable[RelayNode], *, exclude_ids: set[str] | None = None) -> list[RelayNode]:
    excluded = exclude_ids or set()
    return [
        relay for relay in relays
        if relay.online
        and relay.role == "middle"
        and relay.contributor
        and not relay.official
        and relay.relay_id not in excluded
    ]


CircuitTuple = tuple[RelayNode, RelayNode, tuple[RelayNode, ...], RelayNode]


# Cap on how many contributor chain orderings enumerate_circuits is allowed to
# materialize. With many online contributors the permutation count explodes
# (e.g. 50 contribs choose 3 = 117,600 orderings, 100 choose 3 = 970,200), so
# we sample at most this many distinct random orderings instead. This keeps
# diagnostic "list all circuits" UI calls O(1) memory and choose_circuit O(1).
_MAX_ENUMERATED_CONTRIBUTOR_CHAINS = 64


def _contributor_chains(contribs: list[RelayNode], requested_hops: int) -> list[tuple[RelayNode, ...]]:
    if requested_hops <= 0 or not contribs:
        return [tuple()]
    hop_count = min(max(0, int(requested_hops)), CONTRIBUTOR_MAX_HOPS, len(contribs))
    if hop_count <= 0:
        return [tuple()]

    # Compute total permutations P(n, k) without overflow.
    total_permutations = 1
    n = len(contribs)
    for i in range(hop_count):
        total_permutations *= (n - i)

    if total_permutations <= _MAX_ENUMERATED_CONTRIBUTOR_CHAINS:
        return list(itertools.permutations(contribs, hop_count))

    # Sample distinct orderings without materializing all permutations.
    seen: set[tuple[str, ...]] = set()
    chains: list[tuple[RelayNode, ...]] = []
    while len(chains) < _MAX_ENUMERATED_CONTRIBUTOR_CHAINS:
        chosen = random.sample(contribs, hop_count)
        signature = tuple(node.relay_id for node in chosen)
        if signature in seen:
            continue
        seen.add(signature)
        chains.append(tuple(chosen))
    return chains


def _build_random_contributor_chain(contribs: list[RelayNode], requested_hops: int) -> tuple[RelayNode, ...]:
    """Constant-memory contributor-chain picker for the hot path."""
    if requested_hops <= 0 or not contribs:
        return tuple()
    hop_count = min(max(0, int(requested_hops)), CONTRIBUTOR_MAX_HOPS, len(contribs))
    if hop_count <= 0:
        return tuple()
    return tuple(random.sample(contribs, hop_count))


def enumerate_circuits(
    relays: list[RelayNode],
    preferred_entry_id: str | None = None,
    *,
    contributor_path_enabled: bool = False,
    contributor_hops: int = 0,
    exclude_contributor_ids: set[str] | None = None,
) -> list[CircuitTuple]:
    entries = official_relays_by_role(relays, "entry") or relays_by_role(relays, "entry")
    official_middles = official_relays_by_role(relays, "middle")
    exits = official_relays_by_role(relays, "exit") or relays_by_role(relays, "exit")
    contribs = contributor_middles(relays, exclude_ids=exclude_contributor_ids)

    if not entries:
        raise ValueError("Directory does not contain any enabled entry relays")
    if not official_middles:
        raise ValueError("Directory does not contain any enabled official middle relays")
    if not exits:
        raise ValueError("Directory does not contain any enabled exit relays")
    if preferred_entry_id:
        entries = [relay for relay in entries if relay.relay_id == preferred_entry_id]
        if not entries:
            raise ValueError(f"Preferred entry relay '{preferred_entry_id}' was not found or is disabled")

    chains = _contributor_chains(contribs, contributor_hops) if contributor_path_enabled else [tuple()]
    if contributor_path_enabled and contributor_hops > 0 and not contribs:
        chains = [tuple()]  # fallback to official path

    circuits: list[CircuitTuple] = []
    for entry in entries:
        for middle in official_middles:
            for chain in chains:
                if any(node.relay_id == middle.relay_id for node in chain):
                    continue
                for exit_node in exits:
                    circuits.append((entry, middle, chain, exit_node))
    return circuits


def choose_circuit(
    relays: list[RelayNode],
    preferred_entry_id: str | None = None,
    previous_route: tuple[str, ...] | None = None,
    *,
    contributor_path_enabled: bool = False,
    contributor_hops: int = 0,
    exclude_contributor_ids: set[str] | None = None,
) -> CircuitTuple:
    """Pick a random circuit with constant memory.

    We do NOT enumerate the full Cartesian product of (entries x middles x
    contributor permutations x exits). Instead we sample each component
    independently and retry up to a few times if the sampled circuit happens
    to match the previous route.
    """
    entries = official_relays_by_role(relays, "entry") or relays_by_role(relays, "entry")
    official_middles = official_relays_by_role(relays, "middle")
    exits = official_relays_by_role(relays, "exit") or relays_by_role(relays, "exit")
    contribs = contributor_middles(relays, exclude_ids=exclude_contributor_ids)

    if not entries:
        raise ValueError("Directory does not contain any enabled entry relays")
    if not official_middles:
        raise ValueError("Directory does not contain any enabled official middle relays")
    if not exits:
        raise ValueError("Directory does not contain any enabled exit relays")
    if preferred_entry_id:
        entries = [relay for relay in entries if relay.relay_id == preferred_entry_id]
        if not entries:
            raise ValueError(f"Preferred entry relay '{preferred_entry_id}' was not found or is disabled")

    def _sample_once() -> CircuitTuple:
        entry = random.choice(entries)
        middle = random.choice(official_middles)
        chain: tuple[RelayNode, ...] = tuple()
        if contributor_path_enabled and contribs:
            chain = _build_random_contributor_chain(contribs, contributor_hops)
            # Don't repeat the official middle inside the contributor chain.
            if any(node.relay_id == middle.relay_id for node in chain):
                chain = tuple(node for node in chain if node.relay_id != middle.relay_id)
        exit_node = random.choice(exits)
        return (entry, middle, chain, exit_node)

    def sig(candidate: CircuitTuple) -> tuple[str, ...]:
        e, m, c, x = candidate
        return (e.relay_id, m.relay_id, *(node.relay_id for node in c), x.relay_id)

    # If the directory is large enough that randomly hitting the previous
    # route is unlikely, a few retries are sufficient. If it's tiny (e.g. a
    # single entry), we may have no choice but to return the same route.
    last_candidate = None
    for _ in range(8):
        candidate = _sample_once()
        last_candidate = candidate
        if previous_route is None or sig(candidate) != previous_route:
            return candidate
    return last_candidate  # type: ignore[return-value]
