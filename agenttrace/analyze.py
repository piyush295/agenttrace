"""Attack-chain narrative building + risk scoring.

Two deterministic, offline analyses layered on top of detections:

  build_narratives(recon, findings)
      Groups a session's findings into a single multi-stage "kill chain" story,
      ordered by the earliest supporting-evidence timestamp of each stage and
      mapped to a coarse kill-chain phase (initial access -> execution ->
      privilege escalation -> credential access -> collection -> exfiltration).

  score_case(recon, findings)
      Computes per-session and overall risk scores (0-100) from severity,
      chain completeness (how many distinct phases are present), operational
      velocity, and data-sensitivity signals. No ML; fully explainable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .model import Severity
from .correlate import Reconstruction
from .detect import Finding


# Coarse kill-chain phase per pattern (used to order + assess completeness).
_PATTERN_PHASE: dict[str, tuple[int, str]] = {
    "prompt_injection_via_retrieval": (1, "Initial Access / Execution"),
    "tool_permission_escalation":     (2, "Privilege Escalation"),
    "subagent_hijack":                (2, "Privilege Escalation"),
    "memory_poisoning":               (3, "Persistence"),
    "oauth_credential_theft_chain":   (4, "Credential Access"),
    "exfiltration_via_tool_chaining": (5, "Exfiltration"),
}

_SEV_WEIGHT = {Severity.CRITICAL: 40, Severity.HIGH: 25, Severity.MEDIUM: 12,
               Severity.LOW: 5, Severity.INFO: 1}


# --------------------------------------------------------------------------- #
# Narrative
# --------------------------------------------------------------------------- #

@dataclass
class NarrativeStage:
    phase_order: int
    phase: str
    pattern: str
    title: str
    severity: str
    detail: str
    first_seen: Optional[str]
    evidence_event_ids: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in
                ("phase_order", "phase", "pattern", "title", "severity",
                 "detail", "first_seen", "evidence_event_ids")}


@dataclass
class AttackNarrative:
    session_id: Optional[str]
    stages: list[NarrativeStage] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"session_id": self.session_id,
                "summary": self.summary,
                "stages": [s.to_dict() for s in self.stages]}


def _earliest_ts(recon: Reconstruction, event_ids: list[str]) -> Optional[str]:
    best = None
    for eid in event_ids:
        ev = recon.graph.events_by_id.get(eid)
        if ev and ev.timestamp is not None:
            if best is None or ev.timestamp < best:
                best = ev.timestamp
    from .model import to_rfc3339
    return to_rfc3339(best)


def build_narratives(recon: Reconstruction,
                     findings: list[Finding]) -> list[AttackNarrative]:
    by_session: dict[Optional[str], list[Finding]] = {}
    for f in findings:
        by_session.setdefault(f.session_id, []).append(f)

    narratives: list[AttackNarrative] = []
    for session_id, fs in by_session.items():
        stages: list[NarrativeStage] = []
        for f in fs:
            order, phase = _PATTERN_PHASE.get(f.pattern, (9, "Other"))
            stages.append(NarrativeStage(
                phase_order=order, phase=phase, pattern=f.pattern,
                title=f.title, severity=f.severity.value, detail=f.detail,
                first_seen=_earliest_ts(recon, f.evidence_event_ids),
                evidence_event_ids=f.evidence_event_ids,
            ))
        # order by kill-chain phase, then by time
        stages.sort(key=lambda s: (s.phase_order, s.first_seen or ""))

        phases = [s.phase for s in stages]
        summary = _narrative_summary(session_id, stages)
        narratives.append(AttackNarrative(session_id=session_id,
                                          stages=stages, summary=summary))
    # sessions with more/severer stages first
    narratives.sort(key=lambda n: (-len(n.stages),
                                   -sum(_SEV_WEIGHT[_sev(s.severity)]
                                        for s in n.stages)))
    return narratives


def _sev(name: str) -> Severity:
    return Severity(name)


def _narrative_summary(session_id: Optional[str],
                       stages: list[NarrativeStage]) -> str:
    if not stages:
        return "No attack stages reconstructed for this session."
    parts = []
    for s in stages:
        parts.append(f"{s.phase} ({s.pattern})")
    chain = " → ".join(parts)
    n_phases = len({s.phase for s in stages})
    completeness = ("a complete multi-phase kill chain" if n_phases >= 3
                    else "a partial attack chain" if n_phases == 2
                    else "a single-stage indicator")
    return (f"Session '{session_id}' exhibits {completeness}: {chain}.")


# --------------------------------------------------------------------------- #
# Risk scoring
# --------------------------------------------------------------------------- #

@dataclass
class RiskScore:
    session_id: Optional[str]
    score: int              # 0-100
    band: str               # Critical/High/Medium/Low/Minimal
    factors: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"session_id": self.session_id, "score": self.score,
                "band": self.band, "factors": self.factors}


def _band(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    if score >= 15:
        return "Low"
    return "Minimal"


def score_case(recon: Reconstruction,
               findings: list[Finding]) -> dict[str, Any]:
    by_session: dict[Optional[str], list[Finding]] = {}
    for f in findings:
        by_session.setdefault(f.session_id, []).append(f)

    per_session: list[RiskScore] = []
    for session_id, fs in by_session.items():
        sev_component = min(60, sum(_SEV_WEIGHT[f.severity] for f in fs))
        phases = {_PATTERN_PHASE.get(f.pattern, (9, "Other"))[1] for f in fs}
        # chain completeness: more distinct kill-chain phases => higher risk
        completeness = min(30, (len(phases) - 1) * 12) if len(phases) > 1 else 0
        # exfiltration present is a strong multiplier signal
        has_exfil = any(f.pattern == "exfiltration_via_tool_chaining" for f in fs)
        exfil_bonus = 10 if has_exfil else 0

        score = min(100, sev_component + completeness + exfil_bonus)
        per_session.append(RiskScore(
            session_id=session_id, score=score, band=_band(score),
            factors={"severity_component": sev_component,
                     "chain_completeness": completeness,
                     "exfiltration_present": has_exfil,
                     "distinct_phases": sorted(phases),
                     "finding_count": len(fs)},
        ))

    per_session.sort(key=lambda r: -r.score)
    overall = max((r.score for r in per_session), default=0)
    return {
        "overall_score": overall,
        "overall_band": _band(overall),
        "per_session": [r.to_dict() for r in per_session],
    }
