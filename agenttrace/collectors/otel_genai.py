"""Collector for OpenTelemetry GenAI spans.

Maps spans that use the OpenTelemetry GenAI semantic conventions (`gen_ai.*`
attributes) into UnifiedForensicEvents.

Accepted input shapes (JSON):
  * A JSON array of span objects, or
  * A JSON object with a top-level "spans" array, or
  * JSONL where each line is a span object.

Each span is expected to carry (subset of) OTel GenAI attributes such as:
  gen_ai.operation.name    -> "chat" | "execute_tool" | "embeddings" | ...
  gen_ai.system            -> "openai" | "anthropic" | ...
  gen_ai.request.model     -> model name
  gen_ai.tool.name         -> tool name (for tool spans)
  gen_ai.conversation.id / session.id -> session correlation
Plus standard span fields: trace_id, span_id, parent_span_id, name,
start_time_unix_nano / startTimeUnixNano / start_time.
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


_OP_TO_TYPE = {
    "chat": EventType.LLM_INVOCATION,
    "text_completion": EventType.LLM_INVOCATION,
    "generate_content": EventType.LLM_INVOCATION,
    "embeddings": EventType.RETRIEVAL,
    "execute_tool": EventType.TOOL_CALL,
    "invoke_agent": EventType.AGENT_STEP,
    "create_agent": EventType.SUBAGENT_SPAWN,
}


def _get(d: dict, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


class OTelGenAICollector(Collector):
    name = "otel_genai"

    def sniff(self, path: str, sample: str) -> bool:
        return "gen_ai." in sample or "gen_ai\\." in sample

    def _load_spans(self, raw: bytes) -> list[dict]:
        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            return []
        # Try full JSON first.
        try:
            obj = json.loads(text)
            if isinstance(obj, list):
                return [s for s in obj if isinstance(s, dict)]
            if isinstance(obj, dict):
                if isinstance(obj.get("spans"), list):
                    return [s for s in obj["spans"] if isinstance(s, dict)]
                return [obj]
        except json.JSONDecodeError:
            pass
        # Fall back to JSONL.
        spans: list[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
                if isinstance(o, dict):
                    spans.append(o)
            except json.JSONDecodeError:
                continue
        return spans

    def parse(self, path: str, raw: bytes, artifact_id: str) -> Iterable[UnifiedForensicEvent]:
        for span in self._load_spans(raw):
            attrs = span.get("attributes") or {}
            # OTLP sometimes nests attributes as list of {key,value}; normalize.
            if isinstance(attrs, list):
                flat: dict[str, Any] = {}
                for kv in attrs:
                    if isinstance(kv, dict) and "key" in kv:
                        v = kv.get("value")
                        if isinstance(v, dict):
                            v = next(iter(v.values()), None)
                        flat[kv["key"]] = v
                attrs = flat

            op = _get(attrs, "gen_ai.operation.name", default=span.get("name", "other"))
            etype = _OP_TO_TYPE.get(str(op), EventType.OTHER)

            ts = parse_timestamp(
                _get(span, "start_time_unix_nano", "startTimeUnixNano",
                     "start_time", "startTime", "timestamp")
            )
            session_id = _get(attrs, "gen_ai.conversation.id", "session.id",
                              "gen_ai.session.id")
            trace_id = _get(span, "trace_id", "traceId")
            span_id = _get(span, "span_id", "spanId")
            parent = _get(span, "parent_span_id", "parentSpanId")
            actor = _get(attrs, "gen_ai.agent.name", "gen_ai.system", "service.name")
            model = _get(attrs, "gen_ai.request.model", "gen_ai.response.model")
            tool = _get(attrs, "gen_ai.tool.name")

            target = tool or model
            action = str(op)

            # Content summary: prefer explicit prompt/response bodies if present.
            content = _get(attrs, "gen_ai.prompt", "gen_ai.completion",
                           "gen_ai.input.messages", "gen_ai.output.messages")
            content_hash = sha256_hex(json.dumps(content, default=str)) if content else None

            data_refs: list[str] = []
            for k in ("gen_ai.tool.call.arguments", "db.collection.name",
                      "gen_ai.data_source.id"):
                v = attrs.get(k)
                if v:
                    data_refs.append(str(v))

            eid = _get(span, "span_id", "spanId") or make_event_id(
                self.name, trace_id, action, ts
            )
            yield UnifiedForensicEvent(
                event_id=f"{self.name}:{eid}",
                event_type=etype,
                timestamp=ts,
                source=self.name,
                session_id=str(session_id) if session_id else None,
                trace_id=str(trace_id) if trace_id else None,
                span_id=str(span_id) if span_id else None,
                parent_span_id=str(parent) if parent else None,
                actor=str(actor) if actor else None,
                action=action,
                target=str(target) if target else None,
                data_refs=data_refs,
                attributes={"otel_op": str(op), "model": model, "tool": tool},
                content_summary=redact_summary(content) if content else None,
                content_hash=content_hash,
                artifact_id=artifact_id,
            )
