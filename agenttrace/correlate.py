"""Causal-chain reconstruction.

The core investigative capability: take a pile of normalized events (potentially
tens of thousands, spread across sources) and reconstruct *what caused what*.

We build two things:

  1. A chronological, session-scoped **timeline**.
  2. A **causal graph** whose edges express provenance-style relationships,
     inspired by W3C PROV-O:
        - PARENT_OF        : span_id/parent_span_id hierarchy (orchestration)
        - FOLLOWED_BY      : temporal succession within a session
        - USED_DATA        : an event consumed a data_ref produced/seen earlier
        - DERIVED_FROM     : a later event's data_ref traces to an earlier one
                             (e.g. retrieval -> tool call -> egress of same doc)

The key forensic insight this operationalizes: in agent incidents the *sequence*
is the evidence. Correlation stitches the sequence back together across systems
so a detector (Task 6) can recognize a pattern and a report (Task 7) can show it.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .model import EvidenceBundle, EventType, UnifiedForensicEvent


class EdgeType(str, Enum):
    PARENT_OF = "parent_of"        # orchestration hierarchy
    FOLLOWED_BY = "followed_by"    # temporal succession in a session
    USED_DATA = "used_data"        # consumed a data_ref
    DERIVED_FROM = "derived_from"  # data provenance across events


@dataclass
class CausalEdge:
    src: str          # event_id
    dst: str          # event_id
    edge_type: EdgeType
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst,
                "edge_type": self.edge_type.value, "detail": self.detail}


@dataclass
class CausalGraph:
    events_by_id: dict[str, UnifiedForensicEvent] = field(default_factory=dict)
    edges: list[CausalEdge] = field(default_factory=list)

    def add_edge(self, src: str, dst: str, etype: EdgeType, detail: str = "") -> None:
        if src in self.events_by_id and dst in self.events_by_id and src != dst:
            self.edges.append(CausalEdge(src, dst, etype, detail))

    # -- queries used by detectors / report -- #
    def out_edges(self, event_id: str) -> list[CausalEdge]:
        return [e for e in self.edges if e.src == event_id]

    def in_edges(self, event_id: str) -> list[CausalEdge]:
        return [e for e in self.edges if e.dst == event_id]

    def trace_forward(self, event_id: str, max_depth: int = 50) -> list[str]:
        """DFS forward reachability (the downstream 'blast radius' of an event)."""
        seen: list[str] = []
        stack = [(event_id, 0)]
        visited = set()
        while stack:
            node, depth = stack.pop()
            if node in visited or depth > max_depth:
                continue
            visited.add(node)
            if node != event_id:
                seen.append(node)
            for e in self.out_edges(node):
                stack.append((e.dst, depth + 1))
        return seen

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [self.events_by_id[i].to_dict() for i in self.events_by_id],
            "edges": [e.to_dict() for e in self.edges],
        }


@dataclass
class Timeline:
    session_id: Optional[str]
    events: list[UnifiedForensicEvent]

    def to_dict(self) -> dict[str, Any]:
        return {"session_id": self.session_id,
                "events": [e.to_dict() for e in self.events]}


# --------------------------------------------------------------------------- #
# Timeline construction
# --------------------------------------------------------------------------- #

def build_timelines(bundle: EvidenceBundle) -> list[Timeline]:
    """One timeline per session_id; events with no session grouped under None."""
    by_session: dict[Optional[str], list[UnifiedForensicEvent]] = defaultdict(list)
    for ev in bundle.sorted_events():
        by_session[ev.session_id].append(ev)
    timelines = [Timeline(sid, evs) for sid, evs in by_session.items()]
    # Sessions ordered by their earliest dated event.
    def _key(tl: Timeline):
        dated = [e.timestamp for e in tl.events if e.timestamp]
        return (0, min(dated)) if dated else (1, None)
    timelines.sort(key=_key)
    return timelines


# --------------------------------------------------------------------------- #
# Causal graph construction
# --------------------------------------------------------------------------- #

def build_causal_graph(bundle: EvidenceBundle) -> CausalGraph:
    graph = CausalGraph()
    for ev in bundle.events:
        graph.events_by_id[ev.event_id] = ev

    # index by span_id for parent/child edges
    by_span: dict[str, UnifiedForensicEvent] = {}
    for ev in bundle.events:
        if ev.span_id:
            by_span[ev.span_id] = ev

    # 1. PARENT_OF from span hierarchy
    for ev in bundle.events:
        if ev.parent_span_id and ev.parent_span_id in by_span:
            parent = by_span[ev.parent_span_id]
            graph.add_edge(parent.event_id, ev.event_id, EdgeType.PARENT_OF,
                           "orchestration span hierarchy")

    # 2. FOLLOWED_BY within each session (temporal succession)
    for tl in build_timelines(bundle):
        dated = [e for e in tl.events if e.timestamp is not None]
        for a, b in zip(dated, dated[1:]):
            graph.add_edge(a.event_id, b.event_id, EdgeType.FOLLOWED_BY,
                           "next event in session")

    # 3. USED_DATA / DERIVED_FROM via data_refs
    #    When a data_ref first "appears" (e.g. a retrieval), later events that
    #    reference the same data_ref USED it, and are DERIVED_FROM the origin.
    origin_of_ref: dict[str, UnifiedForensicEvent] = {}
    for ev in bundle.sorted_events():
        for ref in ev.data_refs:
            if ref not in origin_of_ref:
                origin_of_ref[ref] = ev
                continue
            origin = origin_of_ref[ref]
            if origin.event_id != ev.event_id:
                graph.add_edge(origin.event_id, ev.event_id, EdgeType.USED_DATA,
                               f"data_ref {ref} used downstream")
                # Egress/tool consuming retrieved data => provenance edge.
                if ev.event_type in (EventType.EGRESS, EventType.TOOL_CALL,
                                     EventType.DATA_ACCESS):
                    graph.add_edge(origin.event_id, ev.event_id,
                                   EdgeType.DERIVED_FROM,
                                   f"{ev.event_type.value} traces to origin of {ref}")
    return graph


@dataclass
class Reconstruction:
    """Bundle of correlation outputs consumed by detection + reporting."""
    timelines: list[Timeline]
    graph: CausalGraph

    def to_dict(self) -> dict[str, Any]:
        return {
            "timelines": [t.to_dict() for t in self.timelines],
            "graph": self.graph.to_dict(),
        }


def reconstruct(bundle: EvidenceBundle) -> Reconstruction:
    """Top-level entry point: build timelines + causal graph."""
    return Reconstruction(
        timelines=build_timelines(bundle),
        graph=build_causal_graph(bundle),
    )
