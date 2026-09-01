"""AgentTrace command-line interface.

Subcommands:
  ingest      ingest evidence files into a case bundle (JSON on disk)
  verify      run integrity + chain-of-custody checks, print/seal manifest
  reconstruct build timeline + causal graph
  detect      run attack-pattern detectors
  report      run the full pipeline and emit a JSON + Markdown report

All operations are local-first and offline. Authorized use only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from . import __version__
from .model import EvidenceBundle
from .collectors import detect_collector, get_collector, all_collectors
from .integrity import verify_bundle
from .correlate import reconstruct
from .detect import detect_all
from .report import build_report, report_json, report_markdown


def _ingest_paths(paths: list[str], case_id: str,
                  force_collector: Optional[str] = None,
                  case_number: Optional[str] = None,
                  case_officer: Optional[str] = None) -> EvidenceBundle:
    from . import new_case
    bundle = new_case(case_id, case_number=case_number, case_officer=case_officer)
    for path in paths:
        if not os.path.isfile(path):
            print(f"warning: skipping non-file {path}", file=sys.stderr)
            continue
        collector = (get_collector(force_collector) if force_collector
                     else detect_collector(path))
        if collector is None:
            print(f"warning: no collector matched {path}", file=sys.stderr)
            continue
        n = collector.ingest(path, bundle)
        print(f"ingested {n:5d} events from {path} via {collector.name}",
              file=sys.stderr)
    return bundle


def _add_common(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("paths", nargs="+", help="evidence files to ingest")
    sp.add_argument("--case-id", default="case-001")
    sp.add_argument("--case-number", default=None,
                    help="official case number for chain of custody")
    sp.add_argument("--case-officer", default=None,
                    help="name of the case officer/custodian performing the work")
    sp.add_argument("--collector", default=None,
                    help=f"force a collector: {[c.name for c in all_collectors()]}")


def _bundle_from_args(args) -> EvidenceBundle:
    return _ingest_paths(args.paths, args.case_id, args.collector,
                         getattr(args, "case_number", None),
                         getattr(args, "case_officer", None))


def cmd_ingest(args) -> int:
    bundle = _bundle_from_args(args)
    print(bundle.to_json())
    return 0


def cmd_verify(args) -> int:
    bundle = _bundle_from_args(args)
    key = args.signing_key.encode() if args.signing_key else None
    manifest = verify_bundle(bundle, signing_key=key)
    print(json.dumps({
        "manifest": manifest,
        "integrity_findings": [f.to_dict() for f in bundle.integrity_findings],
    }, indent=2))
    return 0


def cmd_reconstruct(args) -> int:
    bundle = _bundle_from_args(args)
    recon = reconstruct(bundle)
    print(json.dumps(recon.to_dict(), indent=2, default=str))
    return 0


def cmd_detect(args) -> int:
    bundle = _bundle_from_args(args)
    recon = reconstruct(bundle)
    findings = detect_all(recon)
    print(json.dumps([f.to_dict() for f in findings], indent=2))
    return 0


def cmd_report(args) -> int:
    bundle = _bundle_from_args(args)
    key = args.signing_key.encode() if args.signing_key else None
    manifest = verify_bundle(bundle, signing_key=key)
    recon = reconstruct(bundle)
    findings = detect_all(recon)
    report = build_report(bundle, recon, findings, manifest,
                          case_title=args.title)

    if args.json_out:
        with open(args.json_out, "w") as f:
            f.write(report_json(report))
        print(f"wrote {args.json_out}", file=sys.stderr)
    if args.md_out:
        with open(args.md_out, "w") as f:
            f.write(report_markdown(report, bundle))
        print(f"wrote {args.md_out}", file=sys.stderr)
    if args.html_out:
        from .report import report_html
        with open(args.html_out, "w") as f:
            f.write(report_html(report, recon))
        print(f"wrote {args.html_out}", file=sys.stderr)
    if not args.json_out and not args.md_out and not args.html_out:
        print(report_markdown(report, bundle))
    return 0


def cmd_export(args) -> int:
    """Build a full case and export a portable signed .tar bundle."""
    from .bundle import export_case
    bundle = _bundle_from_args(args)
    key = args.signing_key.encode() if args.signing_key else None
    manifest = verify_bundle(bundle, signing_key=key)
    recon = reconstruct(bundle)
    findings = detect_all(recon)
    report = build_report(bundle, recon, findings, manifest, case_title=args.title)
    seal = export_case(args.out, bundle, manifest, report,
                       signing_key=key, include_evidence=not args.no_evidence)
    print(f"wrote portable case bundle: {args.out}", file=sys.stderr)
    print(json.dumps({"seal_sha256": seal["seal_sha256"],
                      "signed": seal["signature_alg"],
                      "members": list(seal["members"].keys())}, indent=2))
    return 0


def cmd_verify_bundle(args) -> int:
    """Verify a portable .tar case bundle (integrity + signature)."""
    from .bundle import verify_case
    key = args.signing_key.encode() if args.signing_key else None
    result = verify_case(args.tar, signing_key=key)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 2


def cmd_custody(args) -> int:
    """Print + verify the chain-of-custody ledger embedded in a .tar bundle."""
    import tarfile
    from .custody import CustodyLedger
    with tarfile.open(args.tar, "r") as tar:
        try:
            f = tar.extractfile("case/custody.json")
            data = json.loads(f.read()) if f else None
        except KeyError:
            data = None
    if not data:
        print(json.dumps({"error": "no custody ledger found in bundle"}, indent=2))
        return 2
    ledger = CustodyLedger.from_dict(data)
    verification = ledger.verify()
    print(json.dumps({
        "case_number": ledger.case_number,
        "verification": verification,
        "events": [
            {"seq": e.seq, "time": e.timestamp, "action": e.action,
             "custodian": e.custodian, "tool_version": e.tool_version,
             "evidence": len(e.evidence_ids), "note": e.note}
            for e in ledger.events
        ],
    }, indent=2))
    return 0 if verification["ok"] else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agenttrace",
        description="Forensic reconstruction for AI agent security incidents "
                    "(local-first, authorized use only).")
    p.add_argument("--version", action="version", version=f"agenttrace {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    for name, fn in (("ingest", cmd_ingest), ("reconstruct", cmd_reconstruct),
                     ("detect", cmd_detect)):
        sp = sub.add_parser(name)
        _add_common(sp)
        sp.set_defaults(func=fn)

    sp = sub.add_parser("verify")
    _add_common(sp)
    sp.add_argument("--signing-key", default=None)
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("report")
    _add_common(sp)
    sp.add_argument("--signing-key", default=None)
    sp.add_argument("--title", default="AI Agent Incident")
    sp.add_argument("--json-out", default=None)
    sp.add_argument("--md-out", default=None)
    sp.add_argument("--html-out", default=None)
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("export", help="export a portable signed .tar case bundle")
    _add_common(sp)
    sp.add_argument("--out", required=True, help="output .tar path")
    sp.add_argument("--signing-key", default=None)
    sp.add_argument("--title", default="AI Agent Incident")
    sp.add_argument("--no-evidence", action="store_true",
                    help="do not embed copies of original evidence files")
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("verify-bundle",
                        help="verify a portable .tar case bundle")
    sp.add_argument("tar", help="path to the .tar case bundle")
    sp.add_argument("--signing-key", default=None)
    sp.set_defaults(func=cmd_verify_bundle)

    sp = sub.add_parser("custody",
                        help="print + verify the chain-of-custody ledger of a bundle")
    sp.add_argument("tar", help="path to the .tar case bundle")
    sp.set_defaults(func=cmd_custody)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
