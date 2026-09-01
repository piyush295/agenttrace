"""Reporting engine.

Produces a court/regulator-ready incident report from the verified bundle,
reconstruction, detections, and signed manifest. Two renderings:

  * report_json()      -> machine-readable, complete
  * report_markdown()  -> human-readable narrative

The report deliberately includes:
  * an executive summary,
  * a chain-of-custody attestation (artifacts + signed manifest),
  * integrity findings (edited? / missing?),
  * detected attack patterns (IOCs) each linked to supporting evidence,
  * a reconstructed incident timeline,
  * an EU AI Act Article 12 (record-keeping) coverage section, which maps the
    evidence we did / did not find against the record-keeping expectations for a
    high-risk AI system.

Nothing here contacts the network; a report is a pure function of inputs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from .model import EvidenceBundle, Severity, to_rfc3339
from .correlate import Reconstruction
from .detect import Finding


# --------------------------------------------------------------------------- #
# EU AI Act Article 12 coverage
# --------------------------------------------------------------------------- #

def _article12_coverage(bundle: EvidenceBundle) -> list[dict[str, Any]]:
    """Map observed evidence against Article 12 record-keeping expectations.

    Article 12 requires high-risk AI systems to keep logs enabling traceability
    of the system's functioning over its lifecycle. We check whether the evidence
    we ingested supports each expectation, purely from what is present.
    """
    have_types = {e.event_type.value for e in bundle.events}
    have_timestamps = any(e.timestamp for e in bundle.events)
    have_actor = any(e.actor for e in bundle.events)
    have_integrity = any(f.check == "hash_chain" for f in bundle.integrity_findings)
    chain_ok = all(f.ok for f in bundle.integrity_findings if f.check == "hash_chain")

    checks = [
        ("Recording of period of each use (timestamps)",
         have_timestamps,
         "Events carry parseable timestamps." if have_timestamps
         else "No parseable timestamps found — traceability impaired."),
        ("Reference database / inputs the system operated on",
         "retrieval" in have_types or any(e.data_refs for e in bundle.events),
         "Retrieval/data-reference events present."),
        ("Identification of natural persons / actors involved",
         have_actor,
         "Actor/principal recorded on events." if have_actor
         else "No actor attribution present."),
        ("Tamper-evident record integrity",
         have_integrity,
         ("Hash-chain present and verified intact." if have_integrity and chain_ok
          else "Hash-chain present but integrity FAILED." if have_integrity
          else "No tamper-evident integrity mechanism detected in evidence.")),
        ("System actions / decisions (tool calls, outputs)",
         "tool_call" in have_types or "llm_invocation" in have_types,
         "Model and/or tool activity recorded."),
    ]
    return [{"requirement": r, "covered": bool(c), "note": n} for r, c, n in checks]


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #

def build_report(bundle: EvidenceBundle,
                 recon: Reconstruction,
                 findings: list[Finding],
                 manifest: dict[str, Any],
                 case_title: str = "AI Agent Incident") -> dict[str, Any]:
    from .analyze import build_narratives, score_case
    sev_rank = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
                Severity.LOW: 1, Severity.INFO: 0}
    top_sev = max((f.severity for f in findings), default=Severity.INFO,
                  key=lambda s: sev_rank[s])
    integrity_failed = [f for f in bundle.integrity_findings if not f.ok]

    narratives = build_narratives(recon, findings)
    risk = score_case(recon, findings)

    return {
        "report_type": "agenttrace_incident_report",
        "generated_at": to_rfc3339(datetime.now(timezone.utc)),
        "case_id": bundle.case_id,
        "case_title": case_title,
        "executive_summary": {
            "highest_severity": top_sev.value,
            "overall_risk_score": risk["overall_score"],
            "overall_risk_band": risk["overall_band"],
            "attack_patterns_detected": len(findings),
            "artifacts_examined": len(bundle.artifacts),
            "events_examined": len(bundle.events),
            "integrity_issues": len(integrity_failed),
            "sessions_reconstructed": len(recon.timelines),
        },
        "risk": risk,
        "attack_narratives": [n.to_dict() for n in narratives],
        "chain_of_custody": {
            "manifest": manifest,
            "artifacts": [a.to_dict() for a in bundle.artifacts],
        },
        "integrity_findings": [f.to_dict() for f in bundle.integrity_findings],
        "detections": [f.to_dict() for f in findings],
        "timelines": [t.to_dict() for t in recon.timelines],
        "causal_graph_summary": {
            "nodes": len(recon.graph.events_by_id),
            "edges": len(recon.graph.edges),
        },
        "eu_ai_act_article12_coverage": _article12_coverage(bundle),
    }


def report_json(report: dict[str, Any], indent: int = 2) -> str:
    import json
    return json.dumps(report, indent=indent, default=str)


# --------------------------------------------------------------------------- #
# Markdown rendering
# --------------------------------------------------------------------------- #

def _md_table(rows: list[list[str]], header: list[str]) -> str:
    out = ["| " + " | ".join(header) + " |",
           "| " + " | ".join("---" for _ in header) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def report_markdown(report: dict[str, Any], bundle: EvidenceBundle) -> str:
    es = report["executive_summary"]
    lines: list[str] = []
    lines.append(f"# AgentTrace Incident Report — {report['case_title']}")
    lines.append("")
    lines.append(f"- **Case ID:** {report['case_id']}")
    lines.append(f"- **Generated:** {report['generated_at']}")
    lines.append(f"- **Highest severity:** {es['highest_severity'].upper()}")
    lines.append("")
    lines.append("> Authorized-use notice: this report was produced by a defensive "
                 "forensic tool operating on evidence the operator is authorized "
                 "to investigate.")
    lines.append("")

    # Executive summary
    lines.append("## Executive summary")
    lines.append("")
    lines.append(_md_table(
        [[k.replace("_", " ").title(), str(v)] for k, v in es.items()],
        ["Metric", "Value"]))
    lines.append("")

    # Detections
    lines.append("## Detected attack patterns (IOCs)")
    lines.append("")
    if not report["detections"]:
        lines.append("_No known attack patterns matched._")
    else:
        for d in report["detections"]:
            lines.append(f"### [{d['severity'].upper()}] {d['title']}")
            lines.append(f"- **Pattern:** `{d['pattern']}`")
            atlas = d.get("mitre_atlas", {})
            if atlas:
                lines.append(f"- **MITRE ATLAS:** {atlas.get('technique_id')} — "
                             f"{atlas.get('technique')} _({atlas.get('tactic')})_")
            lines.append(f"- **Session:** `{d['session_id']}`")
            lines.append(f"- **Detail:** {d['detail']}")
            ev = ", ".join(f"`{e}`" for e in d["evidence_event_ids"])
            lines.append(f"- **Supporting evidence:** {ev}")
            lines.append("")

    # Attack narratives (kill chains)
    lines.append("## Reconstructed attack narratives (kill chains)")
    lines.append("")
    if not report.get("attack_narratives"):
        lines.append("_No multi-stage narratives reconstructed._")
    else:
        for n in report["attack_narratives"]:
            if not n["stages"]:
                continue
            lines.append(f"### Session `{n['session_id']}`")
            lines.append(f"> {n['summary']}")
            lines.append("")
            rows = [[str(s["phase_order"]), s["phase"], s["pattern"],
                     s["severity"].upper(), s["first_seen"] or "—"]
                    for s in n["stages"]]
            lines.append(_md_table(rows,
                ["#", "Kill-chain phase", "Pattern", "Severity", "First seen"]))
            lines.append("")

    # Risk scoring
    risk = report.get("risk", {})
    lines.append("## Risk assessment")
    lines.append("")
    lines.append(f"**Overall: {risk.get('overall_score', 0)}/100 "
                 f"({risk.get('overall_band', 'Minimal')})**")
    lines.append("")
    if risk.get("per_session"):
        rows = [[str(r["session_id"]), str(r["score"]), r["band"],
                 ", ".join(r["factors"]["distinct_phases"]) or "—"]
                for r in risk["per_session"]]
        lines.append(_md_table(rows,
            ["Session", "Score", "Band", "Kill-chain phases"]))
        lines.append("")

    # Integrity / chain of custody
    lines.append("## Evidence integrity & chain of custody")
    lines.append("")
    man = report["chain_of_custody"]["manifest"]
    lines.append(f"- **Bundle SHA-256:** `{man.get('bundle_sha256')}`")
    lines.append(f"- **Signature:** {man.get('signature_alg') or 'unsigned'}"
                 + (f" `{str(man.get('signature'))[:24]}…`" if man.get('signature') else ""))
    lines.append("")
    if report["integrity_findings"]:
        lines.append(_md_table(
            [[f["check"], "PASS" if f["ok"] else "FAIL",
              f["severity"].upper(), f["detail"]]
             for f in report["integrity_findings"]],
            ["Check", "Result", "Severity", "Detail"]))
        lines.append("")

    # Artifacts
    lines.append("### Artifacts examined")
    lines.append("")
    lines.append(_md_table(
        [[a["artifact_id"], a["source_type"], a["sha256"][:16] + "…",
          str(a["size_bytes"]), a["collector_identity"]]
         for a in report["chain_of_custody"]["artifacts"]],
        ["Artifact", "Source", "SHA-256", "Bytes", "Collected by"]))
    lines.append("")

    # EU AI Act Article 12
    lines.append("## EU AI Act Article 12 (record-keeping) coverage")
    lines.append("")
    lines.append(_md_table(
        [[c["requirement"], "✅" if c["covered"] else "❌", c["note"]]
         for c in report["eu_ai_act_article12_coverage"]],
        ["Requirement", "Covered", "Note"]))
    lines.append("")

    # Timeline (condensed)
    lines.append("## Reconstructed timeline (condensed)")
    lines.append("")
    for tl in report["timelines"]:
        lines.append(f"### Session `{tl['session_id']}`")
        rows = []
        for e in tl["events"][:50]:
            rows.append([e["timestamp"] or "—", e["event_type"],
                         e.get("actor") or "—", e.get("action") or "—",
                         e.get("target") or "—"])
        lines.append(_md_table(rows, ["Time", "Type", "Actor", "Action", "Target"]))
        if len(tl["events"]) > 50:
            lines.append(f"\n_…{len(tl['events']) - 50} more events omitted._")
        lines.append("")

    lines.append("---")
    lines.append(f"_Causal graph: {report['causal_graph_summary']['nodes']} nodes, "
                 f"{report['causal_graph_summary']['edges']} edges._")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# HTML rendering (self-contained, offline, with SVG causal-graph viz)
# --------------------------------------------------------------------------- #

import html as _html
import json as _json


def _severity_color(sev: str) -> str:
    return {"critical": "#b00020", "high": "#e65100", "medium": "#f9a825",
            "low": "#2e7d32", "info": "#546e7a"}.get(sev, "#546e7a")


def _build_graph_layout(recon: "Reconstruction",
                        max_nodes: int = 120) -> dict[str, Any]:
    """Produce a simple deterministic layered layout for the SVG viz.

    Nodes are laid out per-session in columns (x by session) and ordered by time
    (y by event order). Edges reference node ids. Kept small + deterministic so
    the visualization is readable and testable.
    """
    graph = recon.graph
    # choose a representative subset if very large: prioritize nodes that are
    # endpoints of any edge, then fill chronologically.
    edge_nodes: set[str] = set()
    for e in graph.edges:
        edge_nodes.add(e.src)
        edge_nodes.add(e.dst)

    sessions = [t for t in recon.timelines]
    positions: dict[str, dict[str, Any]] = {}
    col_w, row_h = 260, 46
    count = 0
    for col, tl in enumerate(sessions):
        row = 0
        for ev in tl.events:
            if count >= max_nodes:
                break
            # keep edge-connected nodes preferentially when trimming
            if count >= max_nodes // 2 and ev.event_id not in edge_nodes:
                continue
            positions[ev.event_id] = {
                "x": 40 + col * col_w,
                "y": 60 + row * row_h,
                "label": (ev.event_type.value),
                "target": ev.target or "",
                "sev": "info",
            }
            row += 1
            count += 1

    shown = set(positions)
    edges = [{"src": e.src, "dst": e.dst, "type": e.edge_type.value}
             for e in graph.edges if e.src in shown and e.dst in shown]
    width = max(320, 40 + len(sessions) * col_w)
    height = max(200, 60 + (max((len(t.events) for t in sessions), default=1)) * row_h)
    return {"nodes": positions, "edges": edges,
            "width": width, "height": min(height, 60 + max_nodes * row_h)}


def report_html(report: dict[str, Any], recon: "Reconstruction") -> str:
    """Render a self-contained HTML report (no external CDN / network)."""
    es = report["executive_summary"]
    layout = _build_graph_layout(recon)

    def esc(x: Any) -> str:
        return _html.escape(str(x))

    # --- detections cards ---
    det_html = []
    for d in report["detections"]:
        color = _severity_color(d["severity"])
        ev = ", ".join(esc(e) for e in d["evidence_event_ids"][:8])
        det_html.append(f"""
        <div class="card" style="border-left:6px solid {color}">
          <span class="badge" style="background:{color}">{esc(d['severity'].upper())}</span>
          <strong>{esc(d['title'])}</strong>
          <div class="meta">pattern: <code>{esc(d['pattern'])}</code> ·
               session: <code>{esc(d['session_id'])}</code></div>
          <p>{esc(d['detail'])}</p>
          <div class="meta">evidence: {ev}</div>
        </div>""")
    if not report["detections"]:
        det_html.append("<p><em>No known attack patterns matched.</em></p>")

    # --- integrity rows ---
    integ_rows = "".join(
        f"<tr><td>{esc(f['check'])}</td>"
        f"<td class='{'ok' if f['ok'] else 'bad'}'>{'PASS' if f['ok'] else 'FAIL'}</td>"
        f"<td>{esc(f['severity'].upper())}</td><td>{esc(f['detail'])}</td></tr>"
        for f in report["integrity_findings"])

    # --- article 12 rows ---
    a12_rows = "".join(
        f"<tr><td>{esc(c['requirement'])}</td>"
        f"<td>{'✅' if c['covered'] else '❌'}</td><td>{esc(c['note'])}</td></tr>"
        for c in report["eu_ai_act_article12_coverage"])

    # --- artifacts rows ---
    art_rows = "".join(
        f"<tr><td><code>{esc(a['artifact_id'])}</code></td>"
        f"<td>{esc(a['source_type'])}</td>"
        f"<td><code>{esc(a['sha256'][:16])}…</code></td>"
        f"<td>{esc(a['size_bytes'])}</td>"
        f"<td>{esc(a['collector_identity'])}</td></tr>"
        for a in report["chain_of_custody"]["artifacts"])

    man = report["chain_of_custody"]["manifest"]
    graph_json = _json.dumps(layout)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>AgentTrace Report — {esc(report['case_title'])}</title>
<style>
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 0; background:#0f1115; color:#e6e6e6; }}
  header {{ padding:20px 28px; background:#161a22; border-bottom:1px solid #2a2f3a; }}
  h1 {{ margin:0 0 4px; font-size:20px; }}
  main {{ padding:20px 28px; max-width:1100px; }}
  section {{ margin-bottom:28px; }}
  h2 {{ font-size:16px; border-bottom:1px solid #2a2f3a; padding-bottom:6px; }}
  .grid {{ display:flex; gap:14px; flex-wrap:wrap; }}
  .kpi {{ background:#161a22; border:1px solid #2a2f3a; border-radius:10px;
          padding:12px 16px; min-width:130px; }}
  .kpi .n {{ font-size:22px; font-weight:700; }}
  .kpi .l {{ font-size:11px; color:#9aa4b2; text-transform:uppercase; }}
  .card {{ background:#161a22; border-radius:10px; padding:12px 16px; margin:10px 0; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:12px; font-size:11px;
            margin-right:8px; }}
  .meta {{ color:#9aa4b2; font-size:12px; }}
  code {{ color:#7fd1ff; }}
  table {{ border-collapse:collapse; width:100%; font-size:13px; }}
  th, td {{ text-align:left; padding:6px 10px; border-bottom:1px solid #232833; vertical-align:top; }}
  .ok {{ color:#5cd65c; }} .bad {{ color:#ff6b6b; font-weight:700; }}
  .notice {{ background:#1b2330; border:1px solid #2a3547; border-radius:8px;
             padding:10px 14px; font-size:13px; color:#9aa4b2; }}
  svg {{ background:#0b0d12; border:1px solid #2a2f3a; border-radius:10px; }}
  .legend span {{ font-size:11px; margin-right:12px; color:#9aa4b2; }}
</style></head>
<body>
<header>
  <h1>AgentTrace Incident Report — {esc(report['case_title'])}</h1>
  <div class="meta">Case <code>{esc(report['case_id'])}</code> ·
     generated {esc(report['generated_at'])} ·
     highest severity
     <span class="badge" style="background:{_severity_color(es['highest_severity'])}">
       {esc(es['highest_severity'].upper())}</span></div>
</header>
<main>
  <div class="notice">Authorized-use notice: produced by a defensive forensic
    tool operating on evidence the operator is authorized to investigate.</div>

  <section><h2>Executive summary</h2>
    <div class="grid">
      {''.join(f'<div class="kpi"><div class="n">{esc(v)}</div><div class="l">{esc(k.replace("_"," "))}</div></div>' for k,v in es.items())}
    </div>
  </section>

  <section><h2>Detected attack patterns (IOCs)</h2>
    {''.join(det_html)}
  </section>

  <section><h2>Causal graph</h2>
    <div class="legend">
      <span style="color:#7fd1ff">■ parent_of</span>
      <span style="color:#9aa4b2">■ followed_by</span>
      <span style="color:#e6b800">■ used_data</span>
      <span style="color:#ff6b6b">■ derived_from</span>
    </div>
    <svg id="graph" width="{layout['width']}" height="{layout['height']}"></svg>
  </section>

  <section><h2>Evidence integrity &amp; chain of custody</h2>
    <p class="meta">Bundle SHA-256 <code>{esc(man.get('bundle_sha256'))}</code> ·
       signature {esc(man.get('signature_alg') or 'unsigned')}</p>
    <table><tr><th>Check</th><th>Result</th><th>Severity</th><th>Detail</th></tr>
      {integ_rows}</table>
    <h3 style="font-size:13px">Artifacts examined</h3>
    <table><tr><th>Artifact</th><th>Source</th><th>SHA-256</th><th>Bytes</th><th>Collected by</th></tr>
      {art_rows}</table>
  </section>

  <section><h2>EU AI Act Article 12 (record-keeping) coverage</h2>
    <table><tr><th>Requirement</th><th>Covered</th><th>Note</th></tr>{a12_rows}</table>
  </section>
</main>
<script>
  // Offline SVG causal-graph renderer (no external libraries).
  const G = {graph_json};
  const svg = document.getElementById('graph');
  const NS = 'http://www.w3.org/2000/svg';
  const COLOR = {{parent_of:'#7fd1ff', followed_by:'#9aa4b2',
                 used_data:'#e6b800', derived_from:'#ff6b6b'}};
  function el(name, attrs) {{
    const e = document.createElementNS(NS, name);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }}
  for (const edge of G.edges) {{
    const a = G.nodes[edge.src], b = G.nodes[edge.dst];
    if (!a || !b) continue;
    svg.appendChild(el('line', {{x1:a.x+70, y1:a.y+14, x2:b.x+70, y2:b.y+14,
        stroke: COLOR[edge.type] || '#666',
        'stroke-width': edge.type==='derived_from'?2.5:1,
        'stroke-opacity':0.7}}));
  }}
  for (const id in G.nodes) {{
    const n = G.nodes[id];
    const g = el('g', {{}});
    g.appendChild(el('rect', {{x:n.x, y:n.y, rx:6, width:150, height:28,
        fill:'#161a22', stroke:'#2a3547'}}));
    const t = el('text', {{x:n.x+8, y:n.y+18, fill:'#e6e6e6',
        'font-size':'11', 'font-family':'monospace'}});
    t.textContent = n.label + (n.target ? (' · ' + n.target).slice(0,26) : '');
    g.appendChild(t);
    svg.appendChild(g);
  }}
</script>
</body></html>"""
