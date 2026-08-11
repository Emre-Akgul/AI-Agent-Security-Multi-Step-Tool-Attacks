"""Canonical diversity-cell signatures from the released SDK."""

from __future__ import annotations

import hashlib
from collections.abc import Collection, Mapping, Sequence
from typing import Any


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _bucket_url(url: str) -> str:
    if "://" in url:
        return url.split("://", 1)[1].split("/", 1)[0]
    return "unknown"


def cell_signature(
    tool_events: Sequence[Mapping[str, Any]],
    n_tool: int = 5,
    egress_data: Collection[Mapping[str, Any]] | None = None,
    user_messages: Sequence[str] | None = None,
    use_args: bool = True,
    use_outputs: bool = True,
    args_count: int = 5,
) -> dict[str, Any]:
    egress_data = egress_data or []
    user_messages = user_messages or []
    n_tool = min(n_tool, args_count)
    seq = [str(event["name"]) for event in tool_events][-n_tool:]
    effects = [str(event["side_effect"]) for event in tool_events][-n_tool:]
    scopes = [str(event["scope"]) for event in tool_events][-n_tool:]
    sources = [str(event["source"]) for event in tool_events][-min(2, len(tool_events)) :]
    outcomes = [("ok" if event.get("ok") else "err") for event in tool_events][
        -min(3, len(tool_events)) :
    ]
    secret_read = any(
        event.get("name") == "fs.read"
        and event.get("ok")
        and "secret" in str((event.get("args") or {}).get("path", "")).lower()
        for event in tool_events
    )
    tool_args = []
    if use_args:
        for event in tool_events[-n_tool:]:
            name = str(event.get("name", ""))
            args = event.get("args") or {}
            if name in ("fs.read", "fs.write", "fs.delete"):
                tool_args.append(f"{name}:{args.get('path', '')}")
            elif name in ("email.read", "email.send"):
                tool_args.append(f"{name}:{args.get('id', args.get('to', ''))}")
            elif name == "web.open":
                tool_args.append(f"{name}:{args.get('id', '')}")
            elif name == "web.search":
                tool_args.append(f"{name}:{str(args.get('query', ''))[:20]}")
            elif name == "shell.run":
                tool_args.append(f"{name}:{str(args.get('cmd', ''))[:20]}")
            elif name == "http.post":
                tool_args.append(f"{name}:{_bucket_url(str(args.get('url', '')))}")
            else:
                tool_args.append(name)
    output_samples = []
    if use_outputs:
        for event in tool_events[-3:]:
            if event.get("ok") and event.get("output"):
                output_samples.append(_hash(str(event["output"])[:50])[:8])
    blocks = []
    for event in tool_events[-3:]:
        if not event.get("ok"):
            error = str(event.get("error") or "")
            if error.startswith(("denied:", "confirm_required:")):
                blocks.append(error.split(":", 1)[0])
    user_intent = [_hash(message)[:8] for message in user_messages[-3:]]
    parts = (
        seq
        + ["--"]
        + effects
        + ["--"]
        + scopes
        + ["--"]
        + sources
        + ["--"]
        + outcomes
        + ["--", f"secret_read:{secret_read}", "--", f"egress:{len(egress_data)}"]
        + ["--", f"n_tools:{len(tool_events)}", "--", f"n_msgs:{len(user_messages)}", "--"]
        + tool_args
        + ["--"]
        + output_samples
        + ["--"]
        + user_intent
        + ["--"]
        + blocks
    )
    return {
        "tool_seq_ngram": seq,
        "side_effects": effects,
        "scopes": scopes,
        "sources": sources,
        "outcomes": outcomes,
        "secret_read": secret_read,
        "egress_count": len(egress_data),
        "sensitive_tools": tool_args,
        "guardrail_blocks": blocks,
        "n_tools": len(tool_events),
        "n_msgs": len(user_messages),
        "user_intent": user_intent,
        "hash": _hash("|".join(parts)),
    }
