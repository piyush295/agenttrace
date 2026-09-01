"""Collector framework: pluggable evidence ingestion.

A Collector reads a source-native evidence file and yields UnifiedForensicEvents,
while registering an EvidenceArtifact (with hash + chain-of-custody metadata) on
the bundle.

Adding a new source = subclass Collector, implement `sniff` and `parse`, and
register it. The CLI/orchestrator picks the right collector automatically via
`sniff`, or the user can force one by name.
"""

from __future__ import annotations

import getpass
import os
import socket
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Iterable

from ..model import (
    EvidenceArtifact,
    EvidenceBundle,
    UnifiedForensicEvent,
    make_event_id,
    sha256_hex,
)


def collector_identity() -> str:
    """Best-effort identity of who/what performed collection (chain of custody)."""
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    host = socket.gethostname()
    return f"{user}@{host}"


class Collector(ABC):
    """Base class for all evidence collectors."""

    name: str = "base"

    @abstractmethod
    def sniff(self, path: str, sample: str) -> bool:
        """Return True if this collector can handle the file at `path`.

        `sample` is the first few KB of the file (text) for cheap detection.
        """
        raise NotImplementedError

    @abstractmethod
    def parse(self, path: str, raw: bytes, artifact_id: str) -> Iterable[UnifiedForensicEvent]:
        """Parse raw bytes into UnifiedForensicEvents."""
        raise NotImplementedError

    # -- shared ingest driver ---------------------------------------------- #
    def ingest(self, path: str, bundle: EvidenceBundle) -> int:
        """Read file, register artifact, parse events onto the bundle.

        Returns the number of events added.
        """
        with open(path, "rb") as fh:
            raw = fh.read()
        digest = sha256_hex(raw)
        artifact_id = f"art:{digest[:16]}"
        artifact = EvidenceArtifact(
            artifact_id=artifact_id,
            path=os.path.abspath(path),
            source_type=self.name,
            sha256=digest,
            size_bytes=len(raw),
            collected_at=datetime.now(timezone.utc),
            collector_identity=collector_identity(),
        )
        bundle.add_artifact(artifact)
        events = list(self.parse(path, raw, artifact_id))
        bundle.add_events(events)
        return len(events)


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

_REGISTRY: dict[str, Collector] = {}


def register(collector: Collector) -> Collector:
    _REGISTRY[collector.name] = collector
    return collector


def get_collector(name: str) -> Collector:
    if name not in _REGISTRY:
        raise KeyError(f"unknown collector: {name!r} (have: {sorted(_REGISTRY)})")
    return _REGISTRY[name]


def all_collectors() -> list[Collector]:
    return list(_REGISTRY.values())


def detect_collector(path: str) -> Collector | None:
    """Pick a collector by sniffing the file's leading bytes."""
    try:
        with open(path, "rb") as fh:
            sample = fh.read(8192).decode("utf-8", errors="replace")
    except OSError:
        return None
    for collector in _REGISTRY.values():
        try:
            if collector.sniff(path, sample):
                return collector
        except Exception:
            continue
    return None


def _register_builtins() -> None:
    """Import + register built-in collectors (lazy to avoid import cycles).

    Registration order matters for sniff-based detection: specific collectors
    must be tried before the permissive JSONL fallback (jsonl_llm), which is
    registered last.
    """
    from .otel_genai import OTelGenAICollector
    from .halo_record import HaloRecordCollector
    from .mcp import McpCollector
    from .vector_store import VectorStoreCollector
    from .oauth import OAuthCollector
    from .egress import EgressCollector
    from .jsonl_llm import JsonlLlmCollector

    for cls in (OTelGenAICollector, HaloRecordCollector, McpCollector,
                VectorStoreCollector, OAuthCollector, EgressCollector,
                JsonlLlmCollector):
        register(cls())


_register_builtins()
