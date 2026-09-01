"""Collector for RAG vector-store retrieval logs.

Retrieval is the primary evidence source for identifying which document carried
an injection payload. This collector maps retrieval records into RETRIEVAL UFEs,
setting data_refs to the returned chunk/document ids so the prompt-injection
detector can correlate "chunk entered context -> behavior shift".

Recognized record shape (JSONL)::

    {"ts": "...", "retrieval": true, "session_id": "sess-1",
     "query": "how to reset password",
     "results": [{"doc_id": "kb-42", "chunk_id": "kb-42#3", "score": 0.91},
                 {"doc_id": "kb-poisoned", "chunk_id": "kb-poisoned#0", "score": 0.88}],
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


class VectorStoreCollector(Collector):
    name = "vector_store"

    def sniff(self, path: str, sample: str) -> bool:
        has_marker = '"retrieval"' in sample or '"chunk_id"' in sample or '"results"' in sample
        return has_marker and '"query"' in sample and "gen_ai." not in sample

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

            ts = parse_timestamp(rec.get("ts") or rec.get("timestamp"))
            results = rec.get("results") or []
            data_refs: list[str] = []
            scores: list[float] = []
            for r in results:
                if isinstance(r, dict):
                    ref = r.get("chunk_id") or r.get("doc_id")
                    if ref:
                        data_refs.append(str(ref))
                    if isinstance(r.get("score"), (int, float)):
                        scores.append(float(r["score"]))
                else:
                    data_refs.append(str(r))

            yield UnifiedForensicEvent(
                event_id=make_event_id(self.name, rec.get("session_id"), lineno, ts),
                event_type=EventType.RETRIEVAL,
                timestamp=ts,
                source=self.name,
                session_id=rec.get("session_id") or rec.get("session"),
                trace_id=rec.get("trace_id"),
                actor=rec.get("principal") or rec.get("actor"),
                action="retrieve",
                target=rec.get("index") or rec.get("collection") or "vector_store",
                data_refs=data_refs,
                attributes={"scores": scores,
                            "result_count": len(data_refs)},
                content_summary=redact_summary(rec.get("query")),
                artifact_id=artifact_id,
            )
