"""Generate synthetic AI-agent evidence datasets for testing AgentTrace.

Produces realistic-but-fake evidence in multiple source formats, covering:
  * benign activity
  * prompt injection via retrieved content
  * exfiltration via tool-call chaining (with monotonic offsets)
  * OAuth / credential-theft chain (credential access -> EGRESS)
  * a tamper-evident Halo-record chain (intact, plus a helper to tamper)

No real systems, accounts, or data are involved. Timestamps are synthetic.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _chain_hash(prev: str, rec: dict) -> str:
    r = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256((str(prev) + _canon(r)).encode()).hexdigest()


def _t(base: datetime, secs: float) -> str:
    return (base + timedelta(seconds=secs)).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# OTel GenAI spans
# --------------------------------------------------------------------------- #

def otel_span(span_id, parent, op, ts, conv, tool=None, model=None, args=None):
    attrs = {"gen_ai.operation.name": op, "gen_ai.conversation.id": conv}
    if tool:
        attrs["gen_ai.tool.name"] = tool
    if model:
        attrs["gen_ai.request.model"] = model
    if args:
        attrs["gen_ai.tool.call.arguments"] = args
    return {"trace_id": "trace-" + conv, "span_id": span_id,
            "parent_span_id": parent, "name": op, "start_time": ts,
            "attributes": attrs}


def gen_otel_benign(base: datetime) -> list[dict]:
    c = "sess-benign"
    return [
        otel_span("b1", None, "chat", _t(base, 0), c, model="gpt-4o"),
        otel_span("b2", "b1", "execute_tool", _t(base, 1), c, tool="read_file"),
        otel_span("b3", "b1", "chat", _t(base, 2), c, model="gpt-4o"),
        otel_span("b4", "b1", "execute_tool", _t(base, 3), c, tool="read_file"),
    ]


def gen_otel_prompt_injection(base: datetime) -> list[dict]:
    c = "sess-injection"
    spans = [
        otel_span("i1", None, "chat", _t(base, 0), c, model="gpt-4o"),
        otel_span("i2", "i1", "execute_tool", _t(base, 1), c, tool="search_docs"),
        # retrieval brings a poisoned chunk into context
        otel_span("i3", "i1", "embeddings", _t(base, 2), c,
                  args="doc:kb-poisoned-1337"),
        # behaviour shift: brand-new sensitive tool right after retrieval
        otel_span("i4", "i1", "execute_tool", _t(base, 3), c, tool="aws_secrets_get"),
    ]
    return spans


def gen_otel_exfiltration(base: datetime) -> list[dict]:
    c = "sess-exfil"
    spans = [otel_span("x0", None, "chat", _t(base, 0), c, model="gpt-4o")]
    # 25 rapid calls to same endpoint with increasing offsets
    for i in range(25):
        spans.append(otel_span(f"x{i+1}", "x0", "execute_tool", _t(base, 1 + i * 2),
                               c, tool="crm_export", args=f"offset={i*200}"))
    return spans


# --------------------------------------------------------------------------- #
# Halo-record chain (credential-theft chain, with real hash chain)
# --------------------------------------------------------------------------- #

def gen_halo_credential_theft(base: datetime, tamper: bool = False) -> list[dict]:
    c = "sess-oauth-theft"
    raw = [
        {"type": "oauth_grant", "actor": "app:context-ai", "action": "oauth.grant",
         "target": "google-workspace", "summary": "OAuth grant to AI tool",
         "session_id": c},
        {"type": "data_access", "actor": "agent:assistant", "action": "read",
         "target": "aws-secrets-manager", "data_refs": ["secret:ssh-key"],
         "summary": "read private key from secrets manager", "session_id": c},
        {"type": "egress", "actor": "agent:assistant", "action": "http.post",
         "target": "evil-collector.example", "summary": "outbound exfil",
         "session_id": c},
    ]
    # attach timestamps close together (fast operational velocity)
    for i, r in enumerate(raw):
        r["ts"] = _t(base, i * 5)
        r["seq"] = i
    # build the hash chain
    prev = "GENESIS"
    for r in raw:
        r["prev_hash"] = prev
        r["hash"] = _chain_hash(prev, r)
        prev = r["hash"]
    if tamper:
        raw[1]["summary"] = "TAMPERED"  # break the chain without fixing hash
    return raw


# --------------------------------------------------------------------------- #
# Generic JSONL
# --------------------------------------------------------------------------- #

def gen_jsonl_benign(base: datetime) -> list[dict]:
    c = "sess-jsonl"
    return [
        {"ts": _t(base, 0), "type": "llm", "session": c, "prompt": "summarize",
         "response": "ok"},
        {"ts": _t(base, 1), "type": "tool", "session": c, "tool": "calculator",
         "action": "compute"},
    ]


# --------------------------------------------------------------------------- #
# Phase 3 source formats: MCP / vector-store / OAuth / egress
# --------------------------------------------------------------------------- #

def gen_mcp_logs(base: datetime) -> list[dict]:
    c = "sess-mcp"
    return [
        {"ts": _t(base, 0), "mcp": True, "server": "files-mcp", "session_id": c,
         "method": "tools/call", "tool": "read_file",
         "params": {"path": "/app/config.yaml"}, "result_hash": "sha256:aa11",
         "principal": "agent:assistant"},
        {"ts": _t(base, 1), "mcp": True, "server": "shell-mcp", "session_id": c,
         "method": "tools/call", "tool": "exec",
         "params": {"cmd": "env"}, "result_hash": "sha256:bb22",
         "principal": "agent:assistant"},
    ]


def gen_vector_logs(base: datetime) -> list[dict]:
    c = "sess-injection"  # aligns with OTel injection session for cross-source correlation
    return [
        {"ts": _t(base, 0), "retrieval": True, "session_id": c,
         "query": "company travel policy",
         "results": [{"doc_id": "kb-7", "chunk_id": "kb-7#1", "score": 0.93},
                     {"doc_id": "kb-poisoned-1337", "chunk_id": "kb-poisoned-1337#0",
                      "score": 0.90}],
         "principal": "agent:assistant"},
    ]


def gen_oauth_logs(base: datetime) -> list[dict]:
    c = "sess-oauth-theft"
    return [
        {"ts": _t(base, 0), "oauth": True, "session_id": c, "app": "context-ai",
         "user": "alice@corp.example",
         "scopes": ["drive.readonly", "gmail.readonly"], "action": "grant",
         "target": "google-workspace"},
        {"ts": _t(base, 2), "oauth": True, "session_id": c, "app": "context-ai",
         "user": "alice@corp.example", "scopes": ["drive.readonly"],
         "action": "token_use", "target": "google-workspace"},
    ]


def gen_egress_logs(base: datetime) -> list[dict]:
    c = "sess-oauth-theft"
    return [
        {"ts": _t(base, 4), "egress": True, "session_id": c, "method": "POST",
         "host": "collector.evil.example", "dst_ip": "203.0.113.9",
         "bytes": 481200, "url": "https://collector.evil.example/ingest",
         "principal": "agent:assistant"},
    ]


# --------------------------------------------------------------------------- #
# Large-scale dataset (~N events across many sessions) for performance testing
# --------------------------------------------------------------------------- #

def gen_otel_subagent_hijack(base: datetime) -> list[dict]:
    """Sub-agent spawned, which then does credential access + egress."""
    c = "sess-subagent"
    return [
        otel_span("sa0", None, "chat", _t(base, 0), c, model="gpt-4o"),
        otel_span("sa1", "sa0", "create_agent", _t(base, 1), c, tool="spawn:worker"),
        otel_span("sa2", "sa1", "execute_tool", _t(base, 2), c, tool="read_secret_token"),
        otel_span("sa3", "sa1", "execute_tool", _t(base, 3), c, tool="http_post_exfil"),
    ]


def gen_memory_poison_jsonl(base: datetime) -> list[dict]:
    """A memory write whose data_ref is later used by a tool call."""
    c1, c2 = "sess-mem-write", "sess-mem-use"
    return [
        {"ts": _t(base, 0), "type": "memory_op", "session": c1, "action": "write",
         "data_refs": ["mem:instruction-42"], "target": "agent_memory",
         "actor": "agent:assistant"},
        {"ts": _t(base, 60), "type": "tool", "session": c2, "action": "execute",
         "tool": "wire_transfer", "data_refs": ["mem:instruction-42"],
         "actor": "agent:assistant"},
    ]


def gen_tool_escalation_jsonl(base: datetime) -> list[dict]:
    """A sensitive tool invoked with no grant/approval in the session."""
    c = "sess-escalation"
    return [
        {"ts": _t(base, 0), "type": "llm", "session": c, "prompt": "help me",
         "actor": "agent:assistant"},
        {"ts": _t(base, 1), "type": "tool", "session": c, "action": "execute",
         "tool": "admin_delete_user", "actor": "agent:assistant"},
    ]


def gen_scale_otel(base: datetime, target_events: int = 17000) -> list[dict]:
    """Generate ~target_events OTel spans across many benign sessions plus a
    few embedded attack sessions, to test throughput at realistic incident size.
    """
    spans: list[dict] = []
    sessions = max(1, target_events // 20)
    per = 20
    idx = 0
    for s in range(sessions):
        conv = f"scale-sess-{s}"
        root = f"r{s}"
        spans.append(otel_span(root, None, "chat", _t(base, idx), conv, model="gpt-4o"))
        idx += 1
        # sprinkle an attack every 500th session
        attack = (s % 500 == 499)
        for j in range(per - 1):
            if attack and j == 5:
                spans.append(otel_span(f"s{s}_{j}", root, "embeddings",
                                       _t(base, idx), conv, args="doc:poison"))
            elif attack and j == 6:
                spans.append(otel_span(f"s{s}_{j}", root, "execute_tool",
                                       _t(base, idx), conv, tool="aws_secrets_get"))
            else:
                spans.append(otel_span(f"s{s}_{j}", root, "execute_tool",
                                       _t(base, idx), conv, tool="read_file"))
            idx += 1
            if len(spans) >= target_events:
                return spans
    return spans


# --------------------------------------------------------------------------- #
# Writer
# --------------------------------------------------------------------------- #

def write_dataset(out_dir: str) -> dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    base = datetime(2026, 5, 28, 10, 0, 0, tzinfo=timezone.utc)
    paths: dict[str, str] = {}

    otel_all = (gen_otel_benign(base)
                + gen_otel_prompt_injection(base + timedelta(minutes=5))
                + gen_otel_exfiltration(base + timedelta(minutes=10)))
    p = os.path.join(out_dir, "otel_spans.json")
    with open(p, "w") as f:
        json.dump(otel_all, f, indent=2)
    paths["otel"] = p

    halo = gen_halo_credential_theft(base + timedelta(minutes=20))
    p = os.path.join(out_dir, "halo_chain.jsonl")
    with open(p, "w") as f:
        f.write("\n".join(json.dumps(r) for r in halo))
    paths["halo"] = p

    jl = gen_jsonl_benign(base + timedelta(minutes=25))
    p = os.path.join(out_dir, "generic.jsonl")
    with open(p, "w") as f:
        f.write("\n".join(json.dumps(r) for r in jl))
    paths["jsonl"] = p

    # a tampered halo chain for integrity tests
    halo_bad = gen_halo_credential_theft(base + timedelta(minutes=20), tamper=True)
    p = os.path.join(out_dir, "halo_chain_tampered.jsonl")
    with open(p, "w") as f:
        f.write("\n".join(json.dumps(r) for r in halo_bad))
    paths["halo_tampered"] = p

    # Phase 3 formats
    for key, fname, records in (
        ("mcp", "mcp.jsonl", gen_mcp_logs(base + timedelta(minutes=30))),
        ("vector", "vector.jsonl", gen_vector_logs(base + timedelta(minutes=5))),
        ("oauth", "oauth.jsonl", gen_oauth_logs(base + timedelta(minutes=20))),
        ("egress", "egress.jsonl", gen_egress_logs(base + timedelta(minutes=20))),
    ):
        p = os.path.join(out_dir, fname)
        with open(p, "w") as f:
            f.write("\n".join(json.dumps(r) for r in records))
        paths[key] = p

    # Phase 4 attack scenarios
    p = os.path.join(out_dir, "subagent.json")
    with open(p, "w") as f:
        json.dump(gen_otel_subagent_hijack(base + timedelta(minutes=40)), f, indent=2)
    paths["subagent"] = p

    for key, fname, records in (
        ("memory", "memory.jsonl", gen_memory_poison_jsonl(base + timedelta(minutes=45))),
        ("escalation", "escalation.jsonl",
         gen_tool_escalation_jsonl(base + timedelta(minutes=50))),
    ):
        p = os.path.join(out_dir, fname)
        with open(p, "w") as f:
            f.write("\n".join(json.dumps(r) for r in records))
        paths[key] = p

    return paths


def write_scale_dataset(out_dir: str, target_events: int = 17000) -> str:
    """Write a single large OTel spans file (~target_events) for scale testing."""
    os.makedirs(out_dir, exist_ok=True)
    base = datetime(2026, 5, 28, 8, 0, 0, tzinfo=timezone.utc)
    spans = gen_scale_otel(base, target_events)
    p = os.path.join(out_dir, "scale_otel.json")
    with open(p, "w") as f:
        json.dump(spans, f)
    return p


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "synthetic_data"
    written = write_dataset(out)
    for k, v in written.items():
        print(f"{k}: {v}")
