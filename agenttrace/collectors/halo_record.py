"""Collector for Halo-record style hash-chained audit logs.

Halo-record is an open, append-only format: each line is one JSON record of an
agent action (tool call, model call, data access, approval). Every record carries
a hash of the previous record's hash + its own content, forming a tamper-evident
chain.

We ingest each record as a UnifiedForensicEvent AND preserve the chain fields
(seq, prev_hash, hash) in attributes so the integrity verifier can validate the
chain independently.

Assumed record shape (the open format is small and JSON-based)::

    {"seq": 0, "ts": "2026-05-28T10:14:32.441Z", "type": "tool_call",
     "actor": "agent:web-app", "action": "http.get", "target": "api.example.com",
     "data_refs": ["doc:42"], "summary": "...", "content_hash": "...",
     "prev_hash": "GENESIS", "hash": "<sha256 of prev_hash + canonical(record)>"}

The exact hashing recipe is configurable but defaults to:
    hash = sha256(prev_hash + canonical_json(record_without_hash))
which the integrity module re-computes to verify.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from ..model import (
    EventType,
    UnifiedForensicEvent,
    make_event_id,
    parse_timestamp,
    redact_summary,
)
from . import Collector


_TYPE_MAP = {
    "tool_call": EventType.TOOL_CALL,
    "model_call": EventType.LLM_INVOCATION,
    "llm_invocation": EventType.LLM_INVOCATION,
    "data_access": EventType.DATA_ACCESS,
    "approval": EventType.APPROVAL,
    "retrieval": EventType.RETRIEVAL,
    "egress": EventType.EGRESS,
    "oauth_grant": EventType.OAUTH_GRANT,
    "memory_op": EventType.MEMORY_OP,
    "agent_step": EventType.AGENT_STEP,
    "subagent_spawn": EventType.SUBAGENT_SPAWN,
}


class HaloRecordCollector(Collector):
    name = "halo_record"

    def sniff(self, path: str, sample: str) -> bool:
        # Distinctive: hash-chain fields present on JSONL records.
        return ('"prev_hash"' in sample and '"hash"' in sample) or (
            '"seq"' in sample and '"hash"' in sample
        )

    def parse(self, path: str, raw: bytes, artifact_id: str) -> Iterable[UnifiedForensicEvent]:
        text = raw.decode("utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue

            etype = _TYPE_MAP.get(str(rec.get("type", "")), EventType.OTHER)
            ts = parse_timestamp(rec.get("ts") or rec.get("timestamp"))
            seq = rec.get("seq", lineno)
            data_refs = rec.get("data_refs") or []
            if isinstance(data_refs, str):
                data_refs = [data_refs]

            yield UnifiedForensicEvent(
                event_id=f"{self.name}:{seq}:{rec.get('hash', lineno)}",
                event_type=etype,
                timestamp=ts,
                source=self.name,
                session_id=rec.get("session_id") or rec.get("session"),
                trace_id=rec.get("trace_id"),
                span_id=rec.get("span_id"),
                parent_span_id=rec.get("parent_span_id"),
                actor=rec.get("actor"),
                action=rec.get("action"),
                target=rec.get("target"),
                data_refs=[str(d) for d in data_refs],
                attributes={
                    "seq": seq,
                    "prev_hash": rec.get("prev_hash"),
                    "hash": rec.get("hash"),
                    "record": rec,  # preserved verbatim for chain verification
                },
                content_summary=redact_summary(rec.get("summary")),
                content_hash=rec.get("content_hash"),
                artifact_id=artifact_id,
            )
