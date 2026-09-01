"""Attack-pattern detection.

Heuristic detectors for the three attack patterns that account for the majority
of documented 2026 AI-agent incidents. Each detector consumes the correlation
output (timelines + causal graph) and emits Findings that link back to the exact
supporting events, so nothing is an unexplained "black-box" verdict.

Patterns implemented
--------------------
1. prompt_injection_via_retrieval
   A retrieval event brings a document/chunk into context, and immediately
   afterward the agent's tool-call behavior shifts (a tool/target not seen
   earlier in the session) with no corresponding change in user instruction.

2. exfiltration_via_tool_chaining
   The same egress/tool target is called at high volume in a short window, often
   with monotonically increasing offset-like arguments — data being paged out.

3. oauth_credential_theft_chain
   An OAuth grant/token event is followed within a short window by credential/
   secret access and then egress — combined with anomalous operational velocity
   (a multi-step, multi-system chain completed implausibly fast).
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from .model import EventType, Severity, UnifiedForensicEvent
from .correlate import Reconstruction


# --------------------------------------------------------------------------- #
# MITRE ATLAS technique mapping
# --------------------------------------------------------------------------- #
# Maps each detection pattern to MITRE ATLAS (Adversarial Threat Landscape for
# AI Systems) tactic/technique identifiers so findings speak standard threat-
# intel language. IDs follow the ATLAS scheme (AML.Txxxx). These are the
# closest-matching public techniques for each pattern.
ATLAS_MAP: dict[str, dict[str, str]] = {
    "prompt_injection_via_retrieval": {
        "tactic": "ML Attack Staging / Execution",
        "technique_id": "AML.T0051",
        "technique": "LLM Prompt Injection (Indirect, via retrieved content)",
    },
    "exfiltration_via_tool_chaining": {
        "tactic": "Exfiltration",
        "technique_id": "AML.T0057",
        "technique": "LLM Data Leakage / Exfiltration via tool orchestration",
    },
    "oauth_credential_theft_chain": {
        "tactic": "Credential Access / Collection",
        "technique_id": "AML.T0055",
        "technique": "Unsecured Credentials via agent tool access",
    },
    "subagent_hijack": {
        "tactic": "Execution / Privilege Escalation",
        "technique_id": "AML.T0053",
        "technique": "Agent hijacking via spawned sub-agent",
    },
    "memory_poisoning": {
        "tactic": "Persistence / ML Attack Staging",
        "technique_id": "AML.T0070",
        "technique": "Agent memory poisoning (persistent context tampering)",
    },
    "tool_permission_escalation": {
        "tactic": "Privilege Escalation",
        "technique_id": "AML.T0054",
        "technique": "Tool/scope escalation beyond granted permissions",
    },
}


def atlas_for(pattern: str) -> dict[str, str]:
    return ATLAS_MAP.get(pattern, {"tactic": "Unknown", "technique_id": "N/A",
                                    "technique": "Unmapped"})


@dataclass
class Finding:
    pattern: str
    title: str
    severity: Severity
    session_id: Optional[str]
    detail: str
    evidence_event_ids: list[str] = field(default_factory=list)

    @property
    def atlas(self) -> dict[str, str]:
        return atlas_for(self.pattern)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "title": self.title,
            "severity": self.severity.value,
            "session_id": self.session_id,
            "detail": self.detail,
            "evidence_event_ids": self.evidence_event_ids,
            "mitre_atlas": self.atlas,
        }


# --------------------------------------------------------------------------- #
# 1. Prompt injection via retrieved content
# --------------------------------------------------------------------------- #

def detect_prompt_injection_via_retrieval(recon: Reconstruction) -> list[Finding]:
    findings: list[Finding] = []
    for tl in recon.timelines:
        events = [e for e in tl.events if e.timestamp is not None]
        seen_tool_targets: set[str] = set()
        for i, ev in enumerate(events):
            if ev.event_type == EventType.TOOL_CALL and ev.target:
                # record targets seen before any retrieval-triggered shift
                pass
        # Walk the session; when a retrieval happens, look at the next tool call.
        for i, ev in enumerate(events):
            if ev.event_type != EventType.RETRIEVAL:
                if ev.event_type == EventType.TOOL_CALL and ev.target:
                    seen_tool_targets.add(ev.target)
                continue
            # find next tool call after this retrieval
            for nxt in events[i + 1:]:
                if nxt.event_type == EventType.TOOL_CALL and nxt.target:
                    is_new = nxt.target not in seen_tool_targets
                    if is_new:
                        refs = ", ".join(ev.data_refs) or "(unnamed chunk)"
                        findings.append(Finding(
                            pattern="prompt_injection_via_retrieval",
                            title="Behavior shift immediately after content retrieval",
                            severity=Severity.HIGH,
                            session_id=tl.session_id,
                            detail=(f"Retrieval of {refs} was immediately followed by "
                                    f"a NEW tool target '{nxt.target}' not used earlier "
                                    f"in the session. Candidate for injection carried "
                                    f"by retrieved content."),
                            evidence_event_ids=[ev.event_id, nxt.event_id],
                        ))
                    break
    return findings


# --------------------------------------------------------------------------- #
# 2. Exfiltration via tool-call chaining
# --------------------------------------------------------------------------- #

_NUM_RE = re.compile(r"(\d+)")


def _extract_offsets(ev: UnifiedForensicEvent) -> list[int]:
    nums: list[int] = []
    for ref in ev.data_refs:
        nums += [int(n) for n in _NUM_RE.findall(ref)]
    if ev.content_summary:
        nums += [int(n) for n in _NUM_RE.findall(ev.content_summary)]
    return nums


def detect_exfiltration_via_tool_chaining(
        recon: Reconstruction,
        min_calls: int = 20,
        window_seconds: float = 600.0) -> list[Finding]:
    findings: list[Finding] = []
    for tl in recon.timelines:
        by_target: dict[str, list[UnifiedForensicEvent]] = defaultdict(list)
        for ev in tl.events:
            if ev.event_type in (EventType.EGRESS, EventType.TOOL_CALL) and ev.target:
                if ev.timestamp is not None:
                    by_target[ev.target].append(ev)
        for target, evs in by_target.items():
            if len(evs) < min_calls:
                continue
            evs.sort(key=lambda e: e.timestamp)  # type: ignore[arg-type]
            span = (evs[-1].timestamp - evs[0].timestamp).total_seconds()  # type: ignore[operator]
            if span > window_seconds:
                continue
            # monotonic offset signal
            first_offsets = [o for e in evs for o in _extract_offsets(e)]
            monotonic = (len(first_offsets) >= 3 and
                         all(x <= y for x, y in zip(first_offsets, first_offsets[1:])))
            rate = len(evs) / max(span, 1.0)
            findings.append(Finding(
                pattern="exfiltration_via_tool_chaining",
                title="High-volume repeated calls to a single target (paged exfiltration)",
                severity=Severity.CRITICAL if monotonic else Severity.HIGH,
                session_id=tl.session_id,
                detail=(f"{len(evs)} calls to '{target}' within {span:.0f}s "
                        f"({rate:.1f}/s)."
                        + (" Arguments show monotonically increasing offsets, "
                           "consistent with paging a data source out."
                           if monotonic else
                           " Volume/pattern is anomalous even without clear offsets.")),
                evidence_event_ids=[e.event_id for e in evs[:10]],
            ))
    return findings


# --------------------------------------------------------------------------- #
# 3. OAuth / credential-theft chain + operational velocity
# --------------------------------------------------------------------------- #

_CRED_HINTS = re.compile(
    r"(?i)(secret|credential|token|private[_-]?key|password|api[_-]?key|"
    r"secrets?[-_ ]?manager|ssh)"
)


def _looks_like_credential(ev: UnifiedForensicEvent) -> bool:
    hay = " ".join(filter(None, [ev.target, ev.action, ev.content_summary,
                                 " ".join(ev.data_refs)]))
    return bool(_CRED_HINTS.search(hay))


def detect_oauth_credential_theft_chain(
        recon: Reconstruction,
        velocity_seconds: float = 120.0) -> list[Finding]:
    findings: list[Finding] = []
    for tl in recon.timelines:
        events = [e for e in tl.events if e.timestamp is not None]
        # locate oauth or credential-access events
        cred_events = [e for e in events
                       if e.event_type == EventType.OAUTH_GRANT
                       or _looks_like_credential(e)]
        if not cred_events:
            continue
        egress_events = [e for e in events if e.event_type == EventType.EGRESS]
        if not egress_events:
            continue

        # a credential access followed by egress within the window
        for c in cred_events:
            downstream = [e for e in egress_events
                          if e.timestamp >= c.timestamp  # type: ignore[operator]
                          and (e.timestamp - c.timestamp).total_seconds() <= velocity_seconds]  # type: ignore[operator]
            if downstream:
                chain = [c] + downstream
                span = (chain[-1].timestamp - chain[0].timestamp).total_seconds()  # type: ignore[operator]
                findings.append(Finding(
                    pattern="oauth_credential_theft_chain",
                    title="Credential access followed by rapid egress (theft chain)",
                    severity=Severity.CRITICAL,
                    session_id=tl.session_id,
                    detail=(f"Credential/OAuth event ('{c.target or c.action}') was "
                            f"followed by {len(downstream)} egress event(s) within "
                            f"{span:.0f}s — anomalous operational velocity consistent "
                            f"with automated credential exfiltration."),
                    evidence_event_ids=[e.event_id for e in chain[:10]],
                ))
                break
    return findings


# --------------------------------------------------------------------------- #
# 4. Sub-agent hijack
# --------------------------------------------------------------------------- #

def detect_subagent_hijack(recon: Reconstruction) -> list[Finding]:
    """A spawned sub-agent that immediately performs sensitive/egress actions.

    In multi-agent systems, a compromised orchestrator may spawn a sub-agent
    that then does the dirty work. We flag a SUBAGENT_SPAWN whose downstream
    (via causal graph) contains credential access or egress.
    """
    findings: list[Finding] = []
    graph = recon.graph
    for ev in graph.events_by_id.values():
        if ev.event_type != EventType.SUBAGENT_SPAWN:
            continue
        downstream_ids = graph.trace_forward(ev.event_id)
        suspicious = []
        for did in downstream_ids:
            d = graph.events_by_id.get(did)
            if not d:
                continue
            if d.event_type == EventType.EGRESS or _looks_like_credential(d):
                suspicious.append(d)
        if suspicious:
            findings.append(Finding(
                pattern="subagent_hijack",
                title="Spawned sub-agent performed sensitive/egress actions",
                severity=Severity.HIGH,
                session_id=ev.session_id,
                detail=(f"Sub-agent spawned ('{ev.target or ev.action}') led "
                        f"downstream to {len(suspicious)} credential/egress "
                        f"action(s). Treat the spawned session as potentially "
                        f"compromised."),
                evidence_event_ids=[ev.event_id] + [s.event_id for s in suspicious[:9]],
            ))
    return findings


# --------------------------------------------------------------------------- #
# 5. Memory poisoning
# --------------------------------------------------------------------------- #

def detect_memory_poisoning(recon: Reconstruction) -> list[Finding]:
    """A memory WRITE whose stored content is later reflected in a tool target.

    Persistent agent memory can be poisoned so that a later, seemingly-unrelated
    session acts on attacker-planted content. We flag a MEMORY_OP write whose
    data_refs later reappear in a tool call / egress (possibly in another
    session), i.e. the causal graph links the write to downstream use.
    """
    findings: list[Finding] = []
    graph = recon.graph
    writes = [e for e in graph.events_by_id.values()
              if e.event_type == EventType.MEMORY_OP
              and (e.action or "").lower() in ("write", "store", "set", "put", "upsert")]
    for w in writes:
        downstream_ids = graph.trace_forward(w.event_id)
        acted = []
        for did in downstream_ids:
            d = graph.events_by_id.get(did)
            if d and d.event_type in (EventType.TOOL_CALL, EventType.EGRESS):
                acted.append(d)
        # also catch cross-session reuse of the same data_ref
        if not acted and w.data_refs:
            for e in graph.events_by_id.values():
                if e.event_id == w.event_id:
                    continue
                if (set(e.data_refs) & set(w.data_refs)
                        and e.event_type in (EventType.TOOL_CALL, EventType.EGRESS)):
                    acted.append(e)
        if acted:
            findings.append(Finding(
                pattern="memory_poisoning",
                title="Stored memory content later drove tool/egress actions",
                severity=Severity.HIGH,
                session_id=w.session_id,
                detail=(f"Memory write ({', '.join(w.data_refs) or w.action}) was "
                        f"later acted upon by {len(acted)} tool/egress event(s), "
                        f"possibly across sessions — consistent with persistent "
                        f"memory poisoning."),
                evidence_event_ids=[w.event_id] + [a.event_id for a in acted[:9]],
            ))
    return findings


# --------------------------------------------------------------------------- #
# 6. Tool-permission escalation
# --------------------------------------------------------------------------- #

def detect_tool_permission_escalation(recon: Reconstruction) -> list[Finding]:
    """An agent invokes a tool/scope that was never observed being granted.

    We collect granted scopes/tools from OAUTH_GRANT events (data_refs = scopes)
    and APPROVAL events, then flag TOOL_CALLs whose target matches a sensitive
    capability with no corresponding grant/approval earlier in the session.
    """
    findings: list[Finding] = []
    sensitive = re.compile(r"(?i)(admin|secret|delete|exec|shell|payment|"
                           r"transfer|write|deploy|iam|sudo)")
    for tl in recon.timelines:
        events = [e for e in tl.events if e.timestamp is not None]
        granted: set[str] = set()
        approved = False
        for ev in events:
            if ev.event_type == EventType.OAUTH_GRANT:
                for s in ev.data_refs:
                    granted.add(s.lower())
            if ev.event_type == EventType.APPROVAL:
                approved = True
            if ev.event_type == EventType.TOOL_CALL and ev.target:
                tgt = ev.target.lower()
                if sensitive.search(tgt):
                    covered = approved or any(tok in g or g in tgt
                                              for g in granted for tok in [tgt])
                    if not covered and not granted:
                        findings.append(Finding(
                            pattern="tool_permission_escalation",
                            title="Sensitive tool invoked without observed grant/approval",
                            severity=Severity.MEDIUM,
                            session_id=tl.session_id,
                            detail=(f"Tool '{ev.target}' (sensitive capability) was "
                                    f"invoked with no OAuth grant or approval event "
                                    f"observed earlier in the session — possible "
                                    f"permission/scope escalation."),
                            evidence_event_ids=[ev.event_id],
                        ))
    return findings


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

_DETECTORS = [
    detect_prompt_injection_via_retrieval,
    detect_exfiltration_via_tool_chaining,
    detect_oauth_credential_theft_chain,
    detect_subagent_hijack,
    detect_memory_poisoning,
    detect_tool_permission_escalation,
]


def detect_all(recon: Reconstruction) -> list[Finding]:
    findings: list[Finding] = []
    for det in _DETECTORS:
        findings += det(recon)
    # Order by severity (critical first) then session.
    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
             Severity.LOW: 3, Severity.INFO: 4}
    findings.sort(key=lambda f: (order[f.severity], str(f.session_id)))
    return findings
