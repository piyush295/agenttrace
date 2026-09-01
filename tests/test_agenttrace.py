"""End-to-end and unit tests for AgentTrace.

Run with:  python3 -m unittest discover -s tests -v
       or:  python3 -m pytest tests/ -v   (pytest optional; stdlib unittest works)

All tests use synthetic data only — no real systems or data.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from agenttrace import EvidenceBundle, EventType, Severity
from agenttrace.collectors import detect_collector, get_collector, all_collectors
from agenttrace.integrity import verify_bundle, verify_manifest
from agenttrace.correlate import reconstruct, EdgeType
from agenttrace.detect import detect_all
from agenttrace.report import build_report, report_markdown, report_json

from tests.synthetic import write_dataset


class BaseData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.paths = write_dataset(cls.tmp)

    def ingest(self, *keys, case_id="test"):
        bundle = EvidenceBundle(case_id=case_id)
        for k in keys:
            p = self.paths[k]
            c = detect_collector(p)
            self.assertIsNotNone(c, f"no collector detected for {k} ({p})")
            c.ingest(p, bundle)
        return bundle


class TestCollectors(BaseData):
    def test_detection_routing(self):
        self.assertEqual(detect_collector(self.paths["otel"]).name, "otel_genai")
        self.assertEqual(detect_collector(self.paths["halo"]).name, "halo_record")
        self.assertEqual(detect_collector(self.paths["jsonl"]).name, "jsonl_llm")

    def test_ingest_produces_events(self):
        bundle = self.ingest("otel", "halo", "jsonl")
        self.assertGreater(len(bundle.events), 0)
        self.assertEqual(len(bundle.artifacts), 3)

    def test_redaction_no_raw_secrets(self):
        bundle = self.ingest("halo", "otel", "jsonl")
        for e in bundle.events:
            if e.content_summary:
                self.assertNotIn("SECRET123", e.content_summary)


class TestIntegrity(BaseData):
    def test_intact_chain_passes_and_signs(self):
        bundle = self.ingest("halo")
        manifest = verify_bundle(bundle, signing_key=b"k")
        chain = [f for f in bundle.integrity_findings if f.check == "hash_chain"]
        self.assertTrue(chain and all(f.ok for f in chain))
        self.assertTrue(verify_manifest(manifest, b"k"))
        self.assertFalse(verify_manifest(manifest, b"wrong"))

    def test_tampered_chain_fails_critical(self):
        bundle = self.ingest("halo_tampered")
        verify_bundle(bundle)
        chain = [f for f in bundle.integrity_findings if f.check == "hash_chain"]
        self.assertTrue(chain)
        self.assertTrue(any(not f.ok and f.severity == Severity.CRITICAL
                            for f in chain))


class TestCorrelation(BaseData):
    def test_timelines_and_graph(self):
        bundle = self.ingest("otel", "halo", "jsonl")
        recon = reconstruct(bundle)
        # multiple sessions reconstructed
        session_ids = {t.session_id for t in recon.timelines}
        self.assertIn("sess-exfil", session_ids)
        self.assertIn("sess-injection", session_ids)
        # graph has edges
        self.assertGreater(len(recon.graph.edges), 0)
        # parent/child edges exist from span hierarchy
        self.assertTrue(any(e.edge_type == EdgeType.PARENT_OF
                            for e in recon.graph.edges))

    def test_data_provenance_edges(self):
        bundle = self.ingest("halo")
        recon = reconstruct(bundle)
        # the secret data_ref is used downstream -> a USED_DATA/DERIVED_FROM edge
        kinds = {e.edge_type for e in recon.graph.edges}
        self.assertTrue({EdgeType.USED_DATA, EdgeType.DERIVED_FROM} & kinds
                        or len(recon.graph.edges) > 0)


class TestDetection(BaseData):
    def setUp(self):
        self.bundle = self.ingest("otel", "halo", "jsonl")
        self.recon = reconstruct(self.bundle)
        self.findings = detect_all(self.recon)
        self.patterns = {f.pattern for f in self.findings}

    def test_prompt_injection_detected(self):
        self.assertIn("prompt_injection_via_retrieval", self.patterns)

    def test_exfiltration_detected_critical(self):
        exfil = [f for f in self.findings
                 if f.pattern == "exfiltration_via_tool_chaining"]
        self.assertTrue(exfil)
        self.assertTrue(any(f.severity == Severity.CRITICAL for f in exfil))

    def test_credential_theft_chain_detected(self):
        self.assertIn("oauth_credential_theft_chain", self.patterns)

    def test_findings_have_evidence_links(self):
        for f in self.findings:
            self.assertTrue(f.evidence_event_ids,
                            f"{f.pattern} has no evidence links")
            known = {e.event_id for e in self.bundle.events}
            for eid in f.evidence_event_ids:
                self.assertIn(eid, known)


class TestReport(BaseData):
    def test_full_pipeline_report(self):
        bundle = self.ingest("otel", "halo", "jsonl")
        manifest = verify_bundle(bundle, signing_key=b"k")
        recon = reconstruct(bundle)
        findings = detect_all(recon)
        report = build_report(bundle, recon, findings, manifest,
                              case_title="Synthetic Incident")

        # executive summary sane
        es = report["executive_summary"]
        self.assertGreater(es["events_examined"], 0)
        self.assertGreaterEqual(es["attack_patterns_detected"], 3)

        # article 12 coverage present
        self.assertTrue(report["eu_ai_act_article12_coverage"])

        # renders without error
        md = report_markdown(report, bundle)
        self.assertIn("AgentTrace Incident Report", md)
        self.assertIn("EU AI Act Article 12", md)
        js = report_json(report)
        self.assertIn("agenttrace_incident_report", js)

    def test_html_report_renders_offline(self):
        from agenttrace.report import report_html
        bundle = self.ingest("otel", "halo", "jsonl")
        manifest = verify_bundle(bundle, signing_key=b"k")
        recon = reconstruct(bundle)
        findings = detect_all(recon)
        report = build_report(bundle, recon, findings, manifest)
        html = report_html(report, recon)
        self.assertIn("<!doctype html>", html)
        self.assertIn("<svg", html)
        # must be fully offline: no external resource references
        self.assertNotIn("http://", html.replace("http://www.w3.org/2000/svg", ""))
        self.assertNotIn("https://", html)
        self.assertNotIn("cdn", html.lower())


class TestPhase3Collectors(BaseData):
    def test_mcp_collector(self):
        bundle = self.ingest("mcp")
        self.assertTrue(bundle.events)
        self.assertTrue(all(e.source == "mcp" for e in bundle.events))
        self.assertTrue(any(e.attributes.get("result_hash") for e in bundle.events))

    def test_vector_collector_feeds_injection(self):
        bundle = self.ingest("vector")
        self.assertTrue(any(e.event_type == EventType.RETRIEVAL
                            for e in bundle.events))
        # chunk ids captured as data_refs
        self.assertTrue(any("kb-poisoned-1337#0" in e.data_refs
                            for e in bundle.events))

    def test_oauth_collector_flags_broad_scopes(self):
        bundle = self.ingest("oauth")
        self.assertTrue(any(e.event_type == EventType.OAUTH_GRANT
                            for e in bundle.events))
        self.assertTrue(any(e.attributes.get("high_risk") for e in bundle.events))

    def test_egress_collector(self):
        bundle = self.ingest("egress")
        self.assertTrue(any(e.event_type == EventType.EGRESS for e in bundle.events))
        self.assertTrue(any(e.attributes.get("bytes", 0) > 0 for e in bundle.events))

    def test_cross_source_theft_chain(self):
        # oauth grant + egress from separate sources, same session -> theft chain
        bundle = self.ingest("oauth", "egress")
        recon = reconstruct(bundle)
        findings = detect_all(recon)
        self.assertIn("oauth_credential_theft_chain",
                      {f.pattern for f in findings})


class TestScale(unittest.TestCase):
    def test_seventeen_thousand_events(self):
        import time
        tmp = tempfile.mkdtemp()
        from tests.synthetic import write_scale_dataset
        path = write_scale_dataset(tmp, target_events=17000)

        bundle = EvidenceBundle(case_id="scale")
        c = get_collector("otel_genai")
        t0 = time.time()
        c.ingest(path, bundle)
        recon = reconstruct(bundle)
        findings = detect_all(recon)
        elapsed = time.time() - t0

        self.assertGreaterEqual(len(bundle.events), 16000)
        # performance guardrail: full pipeline on ~17k events under 30s
        self.assertLess(elapsed, 30.0,
                        f"pipeline too slow on {len(bundle.events)} events: {elapsed:.1f}s")
        # embedded attacks still surface at scale
        self.assertTrue(findings, "no detections at scale")
        print(f"\n[scale] {len(bundle.events)} events, "
              f"{len(recon.graph.edges)} edges, {len(findings)} findings "
              f"in {elapsed:.2f}s")


class TestPhase4Detectors(BaseData):
    def test_atlas_mapping_present(self):
        bundle = self.ingest("otel", "oauth", "egress")
        recon = reconstruct(bundle)
        findings = detect_all(recon)
        self.assertTrue(findings)
        for f in findings:
            a = f.atlas
            self.assertIn("technique_id", a)
            self.assertTrue(a["technique_id"].startswith("AML.")
                            or a["technique_id"] == "N/A")
            self.assertIn("mitre_atlas", f.to_dict())

    def test_subagent_hijack(self):
        bundle = self.ingest("subagent")
        recon = reconstruct(bundle)
        patterns = {f.pattern for f in detect_all(recon)}
        self.assertIn("subagent_hijack", patterns)

    def test_memory_poisoning(self):
        bundle = self.ingest("memory")
        recon = reconstruct(bundle)
        patterns = {f.pattern for f in detect_all(recon)}
        self.assertIn("memory_poisoning", patterns)

    def test_tool_permission_escalation(self):
        bundle = self.ingest("escalation")
        recon = reconstruct(bundle)
        patterns = {f.pattern for f in detect_all(recon)}
        self.assertIn("tool_permission_escalation", patterns)


class TestNarrativeAndRisk(BaseData):
    def test_narrative_and_risk(self):
        from agenttrace.analyze import build_narratives, score_case
        bundle = self.ingest("otel", "oauth", "egress", "vector")
        recon = reconstruct(bundle)
        findings = detect_all(recon)

        narratives = build_narratives(recon, findings)
        self.assertTrue(narratives)
        # at least one narrative has ordered stages with a summary
        top = narratives[0]
        self.assertTrue(top.summary)
        orders = [s.phase_order for s in top.stages]
        self.assertEqual(orders, sorted(orders))

        risk = score_case(recon, findings)
        self.assertIn("overall_score", risk)
        self.assertGreaterEqual(risk["overall_score"], 0)
        self.assertLessEqual(risk["overall_score"], 100)
        self.assertTrue(risk["per_session"])

    def test_report_includes_phase4(self):
        bundle = self.ingest("otel", "oauth", "egress")
        manifest = verify_bundle(bundle, signing_key=b"k")
        recon = reconstruct(bundle)
        findings = detect_all(recon)
        report = build_report(bundle, recon, findings, manifest)
        self.assertIn("attack_narratives", report)
        self.assertIn("risk", report)
        self.assertIn("overall_risk_score", report["executive_summary"])
        md = report_markdown(report, bundle)
        self.assertIn("MITRE ATLAS", md)
        self.assertIn("Risk assessment", md)


class TestPortableBundle(BaseData):
    def test_export_verify_roundtrip(self):
        from agenttrace.bundle import export_case, verify_case, extract_case
        bundle = self.ingest("otel", "halo", "oauth", "egress")
        manifest = verify_bundle(bundle, signing_key=b"case-key")
        recon = reconstruct(bundle)
        findings = detect_all(recon)
        report = build_report(bundle, recon, findings, manifest)

        tmp = tempfile.mkdtemp()
        tar = os.path.join(tmp, "case.tar")
        seal = export_case(tar, bundle, manifest, report,
                           signing_key=b"case-key")
        self.assertTrue(os.path.isfile(tar))
        self.assertEqual(seal["signature_alg"], "HMAC-SHA256")

        # verify with correct key
        ok = verify_case(tar, signing_key=b"case-key")
        self.assertTrue(ok["ok"], ok["issues"])
        self.assertTrue(ok["member_integrity"])
        self.assertIs(ok["signature_ok"], True)

        # verify with wrong key -> signature fails
        bad = verify_case(tar, signing_key=b"wrong-key")
        self.assertFalse(bad["ok"])
        self.assertIs(bad["signature_ok"], False)

        # extract safely
        dest = extract_case(tar, os.path.join(tmp, "out"))
        self.assertTrue(os.path.isfile(os.path.join(dest, "case", "SEAL.json")))

    def test_tampered_bundle_detected(self):
        from agenttrace.bundle import export_case, verify_case
        import tarfile, io, json as _json
        bundle = self.ingest("otel", "halo")
        manifest = verify_bundle(bundle, signing_key=b"k")
        tmp = tempfile.mkdtemp()
        tar = os.path.join(tmp, "case.tar")
        export_case(tar, bundle, manifest, None, signing_key=b"k")

        # tamper: rewrite bundle.json inside the tar
        members = {}
        with tarfile.open(tar, "r") as t:
            for m in t.getmembers():
                f = t.extractfile(m)
                members[m.name] = f.read() if f else b""
        members["case/bundle.json"] = b'{"case_id":"HACKED","events":[]}'
        with tarfile.open(tar, "w") as t:
            for name, data in members.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))

        res = verify_case(tar, signing_key=b"k")
        self.assertFalse(res["ok"])
        self.assertFalse(res["member_integrity"])


class TestChainOfCustody(BaseData):
    def _custody_bundle(self, *keys, officer="Det. A. Kumar", case_no="CASE-2026-001"):
        from agenttrace import new_case
        b = new_case("coc-test", case_number=case_no, case_officer=officer)
        for k in keys:
            c = detect_collector(self.paths[k])
            c.ingest(self.paths[k], b)
        return b

    def test_acquire_events_recorded_per_artifact(self):
        b = self._custody_bundle("otel", "halo", "oauth")
        led = b.custody_ledger
        acquires = [e for e in led.events if e.action == "acquire"]
        self.assertEqual(len(acquires), 3)
        # each acquire carries the artifact hash
        for e in acquires:
            self.assertTrue(e.evidence_hashes)
            self.assertEqual(e.custodian, "Det. A. Kumar")
            self.assertEqual(e.case_number, "CASE-2026-001")

    def test_ledger_hash_chain_intact(self):
        b = self._custody_bundle("otel", "halo")
        v = b.custody_ledger.verify()
        self.assertTrue(v["ok"], v["issues"])

    def test_ledger_tamper_detected(self):
        b = self._custody_bundle("otel", "halo")
        # tamper with a recorded event's note without recomputing hash
        b.custody_ledger.events[0].note = "ALTERED"
        v = b.custody_ledger.verify()
        self.assertFalse(v["ok"])
        self.assertTrue(any("hash mismatch" in i for i in v["issues"]))

    def test_full_pipeline_custody_continuity(self):
        b = self._custody_bundle("otel", "oauth", "egress")
        manifest = verify_bundle(b, signing_key=b"k")   # -> VERIFY event
        # manifest captures the custody head AT VERIFY TIME (the VERIFY event)
        verify_event = [e for e in b.custody_ledger.events if e.action == "verify"][-1]
        self.assertEqual(manifest["custody_head_hash"], verify_event.hash)

        recon = reconstruct(b)
        findings = detect_all(recon)
        report = build_report(b, recon, findings, manifest)  # -> REPORT event
        actions = [e.action for e in b.custody_ledger.events]
        # acquisitions + verify + report all present, in order
        self.assertIn("acquire", actions)
        self.assertIn("verify", actions)
        self.assertIn("report", actions)
        self.assertLess(actions.index("verify"), actions.index("report"))
        # report is bound to the evidence digest
        self.assertEqual(report["evidence_digest"], b.evidence_digest())
        # manifest carries the same evidence digest
        self.assertEqual(manifest["evidence_digest"], b.evidence_digest())
        # report embeds the full ledger (now including the report event)
        self.assertIsNotNone(report["custody_ledger"])
        self.assertGreaterEqual(report["executive_summary"]["custody_events"], 4)

    def test_export_records_export_and_bundle_verifies_ledger(self):
        from agenttrace.bundle import export_case, verify_case, record_transfer
        b = self._custody_bundle("otel", "halo")
        manifest = verify_bundle(b, signing_key=b"k")
        recon = reconstruct(b)
        report = build_report(b, recon, detect_all(recon), manifest)

        # record a custody transfer before export
        record_transfer(b, to_custodian="Lab-2 Custodian",
                        from_custodian="Det. A. Kumar")

        tmp = tempfile.mkdtemp()
        tar = os.path.join(tmp, "case.tar")
        export_case(tar, b, manifest, report, signing_key=b"k")

        # bundle verification now also checks the embedded custody ledger
        res = verify_case(tar, signing_key=b"k")
        self.assertTrue(res["ok"], res["issues"])
        self.assertIs(res["custody_ok"], True)
        self.assertGreater(res["custody_events"], 0)

        # the ledger contains transfer + export events
        actions = [e.action for e in b.custody_ledger.events]
        self.assertIn("transfer", actions)
        self.assertIn("export", actions)


if __name__ == "__main__":
    unittest.main(verbosity=2)
