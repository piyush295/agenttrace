"""Collector for egress network logs.

Egress is frequently the only artifact that identifies the exfiltration endpoint.
This collector maps outbound HTTP/network records into EGRESS UFEs, capturing the
destination host, method, payload size, and timing — feeding both the
exfiltration-via-tool-chaining and credential-theft-chain detectors.

Recognized record shape (JSONL)::

    {"ts": "...", "egress": true, "session_id": "sess-1",
     "method": "POST", "host": "collector.evil.example", "dst_ip": "203.0.113.9",
     "bytes": 24817, "url": "https://collector.evil.example/ingest",
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


# very rough private/internal ranges for "internal vs external" classification
_INTERNAL_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "::1",
                      "172.16.", "172.17.", "172.18.", "172.19.", "172.2",
                      "172.30.", "172.31.")


def _is_internal(ip: str | None) -> bool:
    if not ip:
        return False
    return any(ip.startswith(p) for p in _INTERNAL_PREFIXES)


class EgressCollector(Collector):
    name = "egress"

    def sniff(self, path: str, sample: str) -> bool:
        return ('"egress"' in sample
                or ('"dst_ip"' in sample and '"bytes"' in sample)
                or ('"host"' in sample and '"method"' in sample)) \
            and "gen_ai." not in sample and '"result_hash"' not in sample

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
            host = rec.get("host") or rec.get("url")
            dst_ip = rec.get("dst_ip") or rec.get("ip")
            nbytes = rec.get("bytes") or rec.get("size") or 0

            yield UnifiedForensicEvent(
                event_id=make_event_id(self.name, host, dst_ip, lineno, ts),
                event_type=EventType.EGRESS,
                timestamp=ts,
                source=self.name,
                session_id=rec.get("session_id") or rec.get("session"),
                trace_id=rec.get("trace_id"),
                actor=rec.get("principal") or rec.get("actor"),
                action=rec.get("method") or "egress",
                target=host,
                data_refs=[str(rec.get("url"))] if rec.get("url") else [],
                attributes={"dst_ip": dst_ip,
                            "bytes": nbytes,
                            "internal": _is_internal(dst_ip)},
                content_summary=redact_summary(
                    f"{rec.get('method')} {host} bytes={nbytes}"),
                artifact_id=artifact_id,
            )
