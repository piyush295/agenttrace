"""Portable signed case-bundle export / import.

Packages a complete case — original evidence files, the normalized event bundle,
the signed integrity manifest, and the generated report — into a single .tar
archive that can be carried to an air-gapped machine (USB, secure transfer) and
re-verified there.

Layout inside the .tar::

    case/
      manifest.json          # signed integrity manifest (HMAC)
      bundle.json            # normalized EvidenceBundle (events + artifacts)
      report.json            # full report (if provided)
      evidence/<name>        # copies of the original evidence files
      SEAL.json              # top-level seal: sha256 of each member + HMAC

Verification recomputes each member's sha256 and checks the SEAL's HMAC, so any
alteration in transit (or on the destination) is detected. Fully offline; uses
only the standard library.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import tarfile
import time
from typing import Any, Optional

from .model import EvidenceBundle, sha256_hex


def _hmac_hex(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()


def export_case(out_path: str,
                bundle: EvidenceBundle,
                manifest: dict[str, Any],
                report: Optional[dict[str, Any]] = None,
                signing_key: Optional[bytes] = None,
                include_evidence: bool = True) -> dict[str, Any]:
    """Write a portable .tar case bundle. Returns the SEAL dict."""
    members: dict[str, bytes] = {}
    members["case/manifest.json"] = json.dumps(manifest, indent=2,
                                               default=str).encode()
    members["case/bundle.json"] = bundle.to_json().encode()
    if report is not None:
        members["case/report.json"] = json.dumps(report, indent=2,
                                                  default=str).encode()

    if include_evidence:
        for art in bundle.artifacts:
            try:
                with open(art.path, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            name = f"case/evidence/{os.path.basename(art.path)}"
            members[name] = data

    # SEAL: sha256 of every member + optional HMAC over the concatenated digests
    member_hashes = {name: sha256_hex(data) for name, data in members.items()}
    seal_core = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "case_id": bundle.case_id,
        "members": member_hashes,
    }
    seal_digest = sha256_hex(json.dumps(seal_core, sort_keys=True,
                                        separators=(",", ":")))
    seal: dict[str, Any] = {**seal_core, "seal_sha256": seal_digest,
                            "signature_alg": None, "signature": None}
    if signing_key:
        seal["signature_alg"] = "HMAC-SHA256"
        seal["signature"] = _hmac_hex(signing_key, seal_digest)

    members["case/SEAL.json"] = json.dumps(seal, indent=2).encode()

    with tarfile.open(out_path, "w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(data))
    return seal


def verify_case(tar_path: str,
                signing_key: Optional[bytes] = None) -> dict[str, Any]:
    """Verify a portable case bundle's integrity (and signature if key given).

    Returns a result dict with ok flags and details. Does not extract to disk.
    """
    result: dict[str, Any] = {"ok": False, "member_integrity": True,
                              "signature_ok": None, "issues": []}
    with tarfile.open(tar_path, "r") as tar:
        contents: dict[str, bytes] = {}
        for member in tar.getmembers():
            if not member.isfile():
                continue
            f = tar.extractfile(member)
            if f is not None:
                contents[member.name] = f.read()

    if "case/SEAL.json" not in contents:
        result["issues"].append("missing SEAL.json")
        return result
    seal = json.loads(contents["case/SEAL.json"])

    # 1. recompute each member hash
    for name, expected in seal.get("members", {}).items():
        actual = sha256_hex(contents.get(name, b""))
        if name not in contents:
            result["member_integrity"] = False
            result["issues"].append(f"missing member: {name}")
        elif actual != expected:
            result["member_integrity"] = False
            result["issues"].append(f"hash mismatch: {name}")

    # 2. recompute seal digest
    seal_core = {"created_at": seal["created_at"], "case_id": seal["case_id"],
                 "members": seal["members"]}
    recomputed = sha256_hex(json.dumps(seal_core, sort_keys=True,
                                       separators=(",", ":")))
    seal_digest_ok = (recomputed == seal.get("seal_sha256"))
    if not seal_digest_ok:
        result["issues"].append("seal digest mismatch")

    # 3. verify signature
    if seal.get("signature_alg") == "HMAC-SHA256":
        if signing_key is None:
            result["signature_ok"] = None
            result["issues"].append("signed bundle but no key provided")
        else:
            expected_sig = _hmac_hex(signing_key, seal["seal_sha256"])
            result["signature_ok"] = hmac.compare_digest(
                expected_sig, seal.get("signature", ""))
            if not result["signature_ok"]:
                result["issues"].append("signature verification FAILED")

    result["ok"] = (result["member_integrity"] and seal_digest_ok
                    and (result["signature_ok"] in (True, None)
                         if signing_key is None else result["signature_ok"] is True))
    result["case_id"] = seal.get("case_id")
    result["member_count"] = len(seal.get("members", {}))
    return result


def extract_case(tar_path: str, dest_dir: str) -> str:
    """Safely extract a verified case bundle to a directory (path-traversal safe)."""
    os.makedirs(dest_dir, exist_ok=True)
    with tarfile.open(tar_path, "r") as tar:
        for member in tar.getmembers():
            # prevent path traversal
            member_path = os.path.realpath(os.path.join(dest_dir, member.name))
            if not member_path.startswith(os.path.realpath(dest_dir) + os.sep):
                raise ValueError(f"unsafe path in archive: {member.name}")
        try:
            tar.extractall(dest_dir, filter="data")  # py3.12+: safe filter
        except TypeError:
            tar.extractall(dest_dir)  # older pythons: paths validated above
    return dest_dir
