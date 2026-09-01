"""Integrity & chain-of-custody verification.

This is a core differentiator of AgentTrace: it does not merely trust recorded
evidence, it *verifies* it, and it explicitly separates two very different
guarantees:

  * "Nothing was edited"  -> the hash chain is internally consistent
                             (no record altered or reordered after writing).
  * "Nothing is missing"  -> a separate, weaker inference. A self-held chain
                             CANNOT prove completeness (an operator could delete
                             a record and re-seal). We surface indicators of
                             possible omission (sequence gaps, time gaps) and,
                             when a witness anchor is provided, verify against it.

Functions
---------
verify_bundle(bundle, ...)   -> runs all checks, appends IntegrityFindings, and
                                seals a signed manifest returned to the caller.
verify_hash_chains(bundle)   -> validate Halo-record style chains.
detect_gaps(bundle)          -> sequence/time gap heuristics per chain.
build_manifest(bundle, key)  -> deterministic manifest + HMAC signature.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections import defaultdict
from datetime import timedelta
from typing import Any, Optional

from .model import (
    EvidenceBundle,
    IntegrityFinding,
    Severity,
    UnifiedForensicEvent,
    sha256_hex,
    to_rfc3339,
)


# --------------------------------------------------------------------------- #
# Canonical JSON (stable, for hash recomputation)
# --------------------------------------------------------------------------- #

def canonical_json(obj: Any) -> str:
    """Deterministic JSON encoding: sorted keys, no whitespace, stable separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


# --------------------------------------------------------------------------- #
# Hash-chain verification (Halo-record style)
# --------------------------------------------------------------------------- #

def _recompute_hash(prev_hash: str, record: dict[str, Any]) -> str:
    """Default Halo-record recipe: sha256(prev_hash + canonical(record\\{hash}))."""
    rec = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(
        (str(prev_hash) + canonical_json(rec)).encode("utf-8")
    ).hexdigest()


def verify_hash_chains(bundle: EvidenceBundle) -> list[IntegrityFinding]:
    """Verify each artifact's hash chain (records that carry prev_hash/hash).

    Groups chain-bearing events by artifact, orders by seq, and checks:
      * link continuity: each record's prev_hash == previous record's hash
      * recomputation: each record's hash matches the recomputed value
        (only when we can recompute, i.e. the raw record is preserved)
    """
    findings: list[IntegrityFinding] = []
    by_artifact: dict[Optional[str], list[UnifiedForensicEvent]] = defaultdict(list)

    for ev in bundle.events:
        attrs = ev.attributes or {}
        if attrs.get("hash") is not None and "record" in attrs:
            by_artifact[ev.artifact_id].append(ev)

    for artifact_id, events in by_artifact.items():
        if not events:
            continue
        events.sort(key=lambda e: e.attributes.get("seq", 0))

        broken_links = 0
        bad_recompute = 0
        prev_hash_expected: Optional[str] = None

        for ev in events:
            attrs = ev.attributes
            rec = attrs.get("record", {})
            this_hash = attrs.get("hash")
            this_prev = attrs.get("prev_hash")

            # 1. link continuity (skip the genesis record)
            if prev_hash_expected is not None and this_prev != prev_hash_expected:
                broken_links += 1

            # 2. recomputation
            if isinstance(rec, dict) and this_prev is not None and this_hash is not None:
                recomputed = _recompute_hash(this_prev, rec)
                if recomputed != this_hash:
                    bad_recompute += 1

            prev_hash_expected = this_hash

        chain_ok = broken_links == 0 and bad_recompute == 0
        if chain_ok:
            findings.append(IntegrityFinding(
                artifact_id=artifact_id,
                check="hash_chain",
                ok=True,
                severity=Severity.INFO,
                detail=(f"Hash chain intact across {len(events)} records "
                        f"(no altered/reordered records detected)."),
            ))
        else:
            findings.append(IntegrityFinding(
                artifact_id=artifact_id,
                check="hash_chain",
                ok=False,
                severity=Severity.CRITICAL,
                detail=(f"Hash chain FAILED: {broken_links} broken link(s), "
                        f"{bad_recompute} record(s) whose hash does not match "
                        f"recomputation. Evidence may have been altered or reordered."),
            ))
    return findings


# --------------------------------------------------------------------------- #
# Gap detection ("nothing is missing" is only ever an inference)
# --------------------------------------------------------------------------- #

def detect_gaps(bundle: EvidenceBundle,
                max_time_gap_seconds: float = 3600.0) -> list[IntegrityFinding]:
    """Heuristics for possibly-missing records.

    * Sequence gaps: within a chain, non-contiguous seq numbers.
    * Large time gaps: unusually long silence between consecutive events in a
      session (context-dependent; reported as LOW, purely advisory).
    """
    findings: list[IntegrityFinding] = []

    # -- sequence gaps per artifact chain -- #
    by_artifact: dict[Optional[str], list[int]] = defaultdict(list)
    for ev in bundle.events:
        seq = (ev.attributes or {}).get("seq")
        if isinstance(seq, int):
            by_artifact[ev.artifact_id].append(seq)

    for artifact_id, seqs in by_artifact.items():
        if len(seqs) < 2:
            continue
        seqs.sort()
        expected = set(range(seqs[0], seqs[-1] + 1))
        missing = sorted(expected - set(seqs))
        if missing:
            preview = ", ".join(map(str, missing[:10]))
            findings.append(IntegrityFinding(
                artifact_id=artifact_id,
                check="gap_detection",
                ok=False,
                severity=Severity.HIGH,
                detail=(f"Sequence gap: {len(missing)} record(s) missing "
                        f"(seq: {preview}{'…' if len(missing) > 10 else ''}). "
                        f"A consistent chain does NOT prove completeness."),
            ))
        else:
            findings.append(IntegrityFinding(
                artifact_id=artifact_id,
                check="gap_detection",
                ok=True,
                severity=Severity.INFO,
                detail=f"No sequence gaps across {len(seqs)} numbered records.",
            ))

    # -- large time gaps per session -- #
    by_session: dict[str, list[UnifiedForensicEvent]] = defaultdict(list)
    for ev in bundle.events:
        if ev.session_id and ev.timestamp:
            by_session[ev.session_id].append(ev)

    for session_id, events in by_session.items():
        events.sort(key=lambda e: e.timestamp)  # type: ignore[arg-type]
        for a, b in zip(events, events[1:]):
            delta = (b.timestamp - a.timestamp).total_seconds()  # type: ignore[operator]
            if delta > max_time_gap_seconds:
                findings.append(IntegrityFinding(
                    artifact_id=None,
                    check="time_gap",
                    ok=True,  # advisory, not a failure
                    severity=Severity.LOW,
                    detail=(f"Session {session_id}: {delta/3600:.1f}h silence between "
                            f"{to_rfc3339(a.timestamp)} and {to_rfc3339(b.timestamp)}. "
                            f"Review whether records were purged by retention."),
                ))
    return findings


# --------------------------------------------------------------------------- #
# Witness-anchor verification (optional, addresses completeness)
# --------------------------------------------------------------------------- #

def verify_witness_anchor(bundle: EvidenceBundle,
                          anchor: dict[str, Any]) -> list[IntegrityFinding]:
    """Verify chain head + count against an out-of-band witness anchor.

    A witness (a party outside the operator's control) periodically stores two
    numbers: record count and the head hash. If provided, we can detect deletion
    that a self-held chain cannot. `anchor` = {"artifact_id":..., "count":int,
    "head_hash":str}.
    """
    findings: list[IntegrityFinding] = []
    aid = anchor.get("artifact_id")
    chain = [e for e in bundle.events
             if e.artifact_id == aid and (e.attributes or {}).get("hash")]
    chain.sort(key=lambda e: e.attributes.get("seq", 0))
    if not chain:
        return findings
    actual_count = len(chain)
    actual_head = chain[-1].attributes.get("hash")
    ok = (actual_count == anchor.get("count") and actual_head == anchor.get("head_hash"))
    findings.append(IntegrityFinding(
        artifact_id=aid,
        check="witness_anchor",
        ok=ok,
        severity=Severity.INFO if ok else Severity.CRITICAL,
        detail=(f"Witness anchor {'MATCHES' if ok else 'MISMATCH'}: "
                f"count actual={actual_count} witness={anchor.get('count')}, "
                f"head actual={str(actual_head)[:12]}… "
                f"witness={str(anchor.get('head_hash'))[:12]}…."
                + ("" if ok else " Records may have been deleted after witnessing.")),
    ))
    return findings


# --------------------------------------------------------------------------- #
# Signed manifest (seals the bundle for chain of custody)
# --------------------------------------------------------------------------- #

def build_manifest(bundle: EvidenceBundle,
                   signing_key: Optional[bytes] = None) -> dict[str, Any]:
    """Build a deterministic manifest of all artifacts + a bundle digest.

    If a signing_key is provided, attach an HMAC-SHA256 signature so the sealed
    manifest can be verified later. (HMAC keeps us stdlib-only; a production
    deployment can swap in asymmetric signing.)
    """
    artifacts = [a.to_dict() for a in bundle.artifacts]
    ledger = getattr(bundle, "custody_ledger", None)
    manifest_core = {
        "case_id": bundle.case_id,
        "case_number": bundle.case_number,
        "case_officer": bundle.case_officer,
        "created_at": to_rfc3339(bundle.created_at),
        "evidence_digest": bundle.evidence_digest(),
        "custody_head_hash": (ledger.events[-1].hash
                              if ledger and ledger.events else "GENESIS"),
        "custody_event_count": len(ledger.events) if ledger else 0,
        "artifact_count": len(artifacts),
        "event_count": len(bundle.events),
        "artifacts": sorted(artifacts, key=lambda a: a["artifact_id"]),
    }
    bundle_digest = sha256_hex(canonical_json(manifest_core))
    manifest: dict[str, Any] = {
        **manifest_core,
        "bundle_sha256": bundle_digest,
        "signature_alg": None,
        "signature": None,
    }
    if signing_key:
        sig = hmac.new(signing_key, bundle_digest.encode("utf-8"),
                       hashlib.sha256).hexdigest()
        manifest["signature_alg"] = "HMAC-SHA256"
        manifest["signature"] = sig
    return manifest


def verify_manifest(manifest: dict[str, Any], signing_key: bytes) -> bool:
    """Verify a manifest's HMAC signature."""
    if manifest.get("signature_alg") != "HMAC-SHA256" or not manifest.get("signature"):
        return False
    expected = hmac.new(signing_key, manifest["bundle_sha256"].encode("utf-8"),
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, manifest["signature"])


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def verify_bundle(bundle: EvidenceBundle,
                  signing_key: Optional[bytes] = None,
                  witness_anchors: Optional[list[dict[str, Any]]] = None,
                  ) -> dict[str, Any]:
    """Run all integrity checks, append findings to the bundle, seal a manifest.

    Returns the signed manifest (dict).
    """
    findings: list[IntegrityFinding] = []
    findings += verify_hash_chains(bundle)
    findings += detect_gaps(bundle)
    for anchor in (witness_anchors or []):
        findings += verify_witness_anchor(bundle, anchor)

    for f in findings:
        bundle.add_integrity_finding(f)

    # Chain of custody: record that evidence integrity was verified.
    if getattr(bundle, "custody_ledger", None) is not None:
        from .custody import CustodyAction
        bundle.custody_ledger.record(
            action=CustodyAction.VERIFY,
            custodian=bundle.case_officer,
            evidence_ids=[a.artifact_id for a in bundle.artifacts],
            evidence_hashes=[a.sha256 for a in bundle.artifacts],
            note=(f"Integrity verified: {len(findings)} finding(s), "
                  f"{sum(1 for x in findings if not x.ok)} issue(s)."),
        )

    return build_manifest(bundle, signing_key)
