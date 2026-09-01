"""Collector for Model Context Protocol (MCP) server logs.

The NSA's May 2026 MCP security guidance calls for MCP servers to log every tool
invocation and result with session identity and cryptographic hashes of results.
This collector maps those records into TOOL_CALL UFEs, preserving the result hash
and session identity for correlation and integrity.

Recognized record shape (JSONL)::

    {"ts": "...", "mcp": true, "server": "files-mcp", "session_id": "sess-1",
     "method": "tools/call", "tool": "read_file",
     "params": {"path": "/etc/hosts"}, "result_hash": "sha256:...",
     "principal": "agent:assistant"}
"""

from __future__ import annotations

import json
from typing import Iterable

from ..model import (
    EventType,
    UnifiedForensicEvent,
    make_event_id,
    parse_timestamp,
    redact_summary,
)
from . import Collector


class McpCollector(Collector):
    name = "mcp"

    def sniff(self, path: str, sample: str) -> bool:
        return ('"mcp"' in sample or '"tools/call"' in sample
                or '"result_hash"' in sample) and "gen_ai." not in sample

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

            method = str(rec.get("method", ""))
            etype = (EventType.TOOL_CALL if "tools/call" in method or rec.get("tool")
                     else EventType.OTHER)
            ts = parse_timestamp(rec.get("ts") or rec.get("timestamp"))
            params = rec.get("params") or {}
            data_refs = []
            if isinstance(params, dict):
                for v in params.values():
                    data_refs.append(str(v))

            result_hash = rec.get("result_hash")
            yield UnifiedForensicEvent(
                event_id=make_event_id(self.name, rec.get("server"),
                                       rec.get("session_id"), lineno, ts),
                event_type=etype,
                timestamp=ts,
                source=self.name,
                session_id=rec.get("session_id") or rec.get("session"),
                trace_id=rec.get("trace_id"),
                span_id=rec.get("span_id"),
                actor=rec.get("principal") or rec.get("actor"),
                action=method or "tools/call",
                target=rec.get("tool") or rec.get("server"),
                data_refs=data_refs,
                attributes={"mcp_server": rec.get("server"),
                            "method": method,
                            "result_hash": result_hash},
                content_summary=redact_summary(params),
                content_hash=(result_hash.split(":")[-1]
                              if isinstance(result_hash, str) and ":" in result_hash
                              else result_hash),
                artifact_id=artifact_id,
            )
