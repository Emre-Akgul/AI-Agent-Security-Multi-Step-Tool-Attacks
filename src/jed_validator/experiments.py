"""Compact experiment reports for humans and autonomous coding agents."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .kaggle_runner import KaggleRunnerError


def find_summaries(root: Path) -> list[Path]:
    """Return validation summaries newest first."""

    if root.is_file():
        return [root]
    if (root / "artifacts" / "validation_summary.json").is_file():
        return [root / "artifacts" / "validation_summary.json"]
    if (root / "validation_summary.json").is_file():
        return [root / "validation_summary.json"]
    return sorted(root.glob("*/artifacts/validation_summary.json"), reverse=True)


def load_summary(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise KaggleRunnerError(f"Cannot read experiment summary {path}: {error}") from error
    if not isinstance(value, dict):
        raise KaggleRunnerError(f"Experiment summary must be an object: {path}")
    return value


def _model_row(name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    digest = value.get("finding_digest", {})
    if not isinstance(digest, Mapping):
        digest = {}
    return {
        "model": name,
        "status": value.get("status", "missing"),
        "score": value.get("score_normalized_0_to_1000"),
        "raw_score": value.get("score_raw"),
        "findings": value.get("findings_count"),
        "unique_cells": value.get("unique_canonical_cells", value.get("unique_cells")),
        "predicates": digest.get("predicate_counts", {}),
        "severities": digest.get("severity_counts", {}),
        "tools": digest.get("successful_tool_counts", {}),
        "prompt_chains": digest.get("successful_prompt_chains", []),
    }


def _legacy_finding_digest(summary_path: Path, model_name: str) -> dict[str, Any]:
    """Derive the new compact fields from artifacts produced by the old evaluator."""

    findings_path = summary_path.with_name(f"{model_name}_findings.json")
    if not findings_path.is_file():
        return {}
    try:
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(findings, list):
        return {}
    predicates: dict[str, int] = {}
    prompts: list[list[str]] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        messages = finding.get("user_messages")
        if isinstance(messages, list) and all(isinstance(message, str) for message in messages):
            prompts.append(messages)
        for predicate in finding.get("predicates", []):
            if isinstance(predicate, Mapping):
                name = str(predicate.get("predicate", "unknown"))
                predicates[name] = predicates.get(name, 0) + 1
    return {"predicate_counts": predicates, "successful_prompt_chains": prompts}


def build_report(summary: Mapping[str, Any], summary_path: Path) -> dict[str, Any]:
    models = summary.get("models", {})
    rows = []
    if isinstance(models, Mapping):
        for name, value in models.items():
            if not isinstance(value, Mapping):
                continue
            row = _model_row(str(name), value)
            if not row["predicates"] and not row["prompt_chains"]:
                digest = _legacy_finding_digest(summary_path, str(name))
                row["predicates"] = digest.get("predicate_counts", {})
                row["prompt_chains"] = digest.get("successful_prompt_chains", [])
            rows.append(row)
    prompt_sets = [
        {tuple(chain) for chain in row["prompt_chains"] if isinstance(chain, list)} for row in rows
    ]
    shared = set.intersection(*prompt_sets) if prompt_sets else set()
    return {
        "summary_path": str(summary_path),
        "status": summary.get("status"),
        "profile": summary.get("profile", "legacy"),
        "attack_sha256": summary.get("attack_sha256"),
        "models_requested": summary.get("requested_models", list(models) if models else []),
        "budget_s_per_model": summary.get("budget_s_per_model"),
        "mean_score": summary.get("mean_score", summary.get("local_public_mean")),
        "models": rows,
        "shared_successful_prompt_chains": [list(chain) for chain in sorted(shared)],
        "failures": summary.get("failures", {}),
    }


def latest_report(root: Path) -> dict[str, Any]:
    summaries = find_summaries(root)
    if not summaries:
        raise KaggleRunnerError(f"No validation runs found under {root}")
    return build_report(load_summary(summaries[0]), summaries[0])


def history(root: Path, limit: int = 20) -> list[dict[str, Any]]:
    rows = []
    for path in find_summaries(root)[:limit]:
        report = build_report(load_summary(path), path)
        rows.append(
            {
                "run": path.parents[1].name,
                "profile": report["profile"],
                "sha": str(report["attack_sha256"] or "")[:12],
                "models": ",".join(report["models_requested"]),
                "budget_s": report["budget_s_per_model"],
                "mean_score": report["mean_score"],
                "status": report["status"],
            }
        )
    return rows


def print_report(report: Mapping[str, Any]) -> None:
    print(
        f"profile={report.get('profile')}  mean={report.get('mean_score')}  "
        f"sha={str(report.get('attack_sha256', ''))[:12]}"
    )
    for model in report.get("models", []):
        print(
            f"{model['model']:<8} score={model['score']} raw={model['raw_score']} "
            f"findings={model['findings']} cells={model['unique_cells']}"
        )
        print(f"         predicates={json.dumps(model['predicates'], sort_keys=True)}")
    shared = report.get("shared_successful_prompt_chains", [])
    if shared:
        print(f"shared successful chains: {len(shared)}")
        for chain in shared[:10]:
            print(f"  - {' -> '.join(chain)}")


def print_history(rows: Sequence[Mapping[str, Any]]) -> None:
    print("run                                  profile models          budget  mean      status")
    for row in rows:
        mean = "-" if row["mean_score"] is None else f"{float(row['mean_score']):.6g}"
        print(
            f"{row['run']:<36} {str(row['profile']):<7} {str(row['models']):<15} "
            f"{str(row['budget_s']):<7} {mean:<9} {row['status']}"
        )
