"""Collector for OAuth grant / token issuance & use records.

OAuth sprawl was the enabling precondition of documented 2026 breaches (e.g. the
Vercel April 2026 incident). This collector maps grant/token records into
OAUTH_GRANT UFEs so the credential-theft-chain detector can flag a grant/use
followed by rapid egress, and so reports can enumerate active grants + scopes.

Recognized record shape (JSONL)::

    {"ts": "...", "oauth": true, "session_id": "sess-1",
     "app": "context-ai", "user": "alice@corp.example",
     "scopes": ["drive.readonly", "gmail.readonly"],
     "action": "grant"|"token_use", "target": "google-workspace"}
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


# scopes considered high-risk for blast-radius assessment
_BROAD_SCOPES = ("drive", "gmail", "mail", "calendar", "admin", "full",
                 "read_write", "repo", "*")


class OAuthCollector(Collector):
    name = "oauth"

    def sniff(self, path: str, sample: str) -> bool:
        return ('"oauth"' in sample or '"scopes"' in sample
                or '"token_use"' in sample) and "gen_ai." not in sample

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
            scopes = rec.get("scopes") or []
            if isinstance(scopes, str):
                scopes = [scopes]
            broad = [s for s in scopes
                     if any(b in str(s).lower() for b in _BROAD_SCOPES)]

            yield UnifiedForensicEvent(
                event_id=make_event_id(self.name, rec.get("app"),
                                       rec.get("user"), lineno, ts),
                event_type=EventType.OAUTH_GRANT,
                timestamp=ts,
                source=self.name,
                session_id=rec.get("session_id") or rec.get("session"),
                actor=rec.get("app") or rec.get("actor"),
                action=rec.get("action") or "grant",
                target=rec.get("target") or rec.get("provider"),
                data_refs=[str(s) for s in scopes],
                attributes={"user": rec.get("user"),
                            "scopes": [str(s) for s in scopes],
                            "broad_scopes": broad,
                            "high_risk": bool(broad)},
                content_summary=redact_summary(
                    f"app={rec.get('app')} scopes={scopes}"),
                artifact_id=artifact_id,
            )
