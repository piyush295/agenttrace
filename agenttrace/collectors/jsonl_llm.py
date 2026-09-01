"""Collector for generic JSONL LLM invocation / tool logs.

A permissive fallback for the common case where a team exported agent logs as
JSONL without following OTel or Halo-record. Each line is a JSON object; we map
common field names heuristically.

Recognized-ish fields (any subset):
    ts/timestamp/time, type/kind/event, session_id/session/conversation_id,
    trace_id, span_id, actor/user/agent, action/operation, target/tool/url,
    prompt/response/input/output/messages, data_refs/documents.
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
    sha256_hex,
)
from . import Collector


_TYPE_HINTS = {
    "llm": EventType.LLM_INVOCATION,
    "chat": EventType.LLM_INVOCATION,
    "completion": EventType.LLM_INVOCATION,
    "model": EventType.LLM_INVOCATION,
    "tool": EventType.TOOL_CALL,
    "function": EventType.TOOL_CALL,
    "retrieval": EventType.RETRIEVAL,
    "rag": EventType.RETRIEVAL,
    "egress": EventType.EGRESS,
    "http": EventType.EGRESS,
    "oauth": EventType.OAUTH_GRANT,
    "memory": EventType.MEMORY_OP,
    "memory_op": EventType.MEMORY_OP,
    "subagent": EventType.SUBAGENT_SPAWN,
    "approval": EventType.APPROVAL,
}


def _first(d: dict, *keys: str) -> Any:
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None


def _infer_type(rec: dict) -> EventType:
    raw = str(_first(rec, "type", "kind", "event", "operation") or "").lower()
    for hint, et in _TYPE_HINTS.items():
        if hint in raw:
            return et
    if _first(rec, "tool", "tool_name", "function"):
        return EventType.TOOL_CALL
    if _first(rec, "prompt", "messages", "completion", "response"):
        return EventType.LLM_INVOCATION
    if _first(rec, "url", "host", "destination"):
        return EventType.EGRESS
    return EventType.OTHER


class JsonlLlmCollector(Collector):
    name = "jsonl_llm"

    def sniff(self, path: str, sample: str) -> bool:
        # Lowest-priority fallback: looks like JSONL objects but not the others.
        if "gen_ai." in sample:
            return False
        if '"prev_hash"' in sample:
            return False
        stripped = sample.lstrip()
        return stripped.startswith("{") and '"' in stripped

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

            etype = _infer_type(rec)
            ts = parse_timestamp(_first(rec, "ts", "timestamp", "time"))
            content = _first(rec, "prompt", "messages", "input", "completion",
                             "response", "output")
            content_hash = (
                sha256_hex(json.dumps(content, default=str)) if content else None
            )
            data_refs = _first(rec, "data_refs", "documents", "doc_ids") or []
            if isinstance(data_refs, str):
                data_refs = [data_refs]

            eid = _first(rec, "id", "event_id", "span_id") or make_event_id(
                self.name, lineno, ts, etype.value
            )
            yield UnifiedForensicEvent(
                event_id=f"{self.name}:{eid}",
                event_type=etype,
                timestamp=ts,
                source=self.name,
                session_id=_first(rec, "session_id", "session", "conversation_id"),
                trace_id=_first(rec, "trace_id", "traceId"),
                span_id=_first(rec, "span_id", "spanId"),
                parent_span_id=_first(rec, "parent_span_id", "parentSpanId"),
                actor=_first(rec, "actor", "user", "agent", "principal"),
                action=_first(rec, "action", "operation", "method"),
                target=_first(rec, "target", "tool", "tool_name", "url", "host"),
                data_refs=[str(d) for d in data_refs],
                attributes={"raw_type": _first(rec, "type", "kind", "event")},
                content_summary=redact_summary(content) if content else None,
                content_hash=content_hash,
                artifact_id=artifact_id,
            )
