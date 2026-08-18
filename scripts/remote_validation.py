"""Competition-matched evaluator executed as a private Kaggle script.

The local runner replaces the injection marker below in a temporary copy.  This
source file remains normal Python so it can be reviewed, linted, and tested.
"""

from __future__ import annotations

# __JED_RUN_CONFIGURATION__

# Defaults make this source statically checkable. The staged script defines these
# names above this block, so the fallback never overwrites a real run configuration.
if "ATTACK_SHA256" not in globals():
    ATTACK_SHA256 = "not-injected"
    ATTACK_PAYLOAD_B64 = ""
    REQUESTED_MODELS = ("gpt_oss", "gemma")
    REQUESTED_BUDGET_S = 8750.0
    RUN_PROFILE = "unstaged"

import gc
import hashlib
import importlib
import importlib.util
import json
import os
import subprocess
import sys
import time
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

COMP_DIR = Path("/kaggle/input/competitions/ai-agent-security-multi-step-tool-attacks")
WORK_DIR = Path("/kaggle/working")
ARTIFACTS_DIR = WORK_DIR / "artifacts"
ATTACK_PATH = WORK_DIR / "attack.py"

MODEL_CONFIG = {
    "gpt_oss": {
        "path": Path(
            "/kaggle/input/models/llkh0a/gpt-oss-20b-gguf/pytorch/default/1/"
            "gpt_oss/gpt-oss-20b-Q4_K_M.gguf"
        ),
        "module": "gpt_oss_model_server",
    },
    "gemma": {
        "path": Path(
            "/kaggle/input/models/llkh0a/gemma-4-26b-a4b-it-ud-q4-k-m-gguf/"
            "pytorch/default/1/gemma/gemma-4-26B-A4B-it-UD-Q4_K_M.gguf"
        ),
        "module": "gemma_model_server",
    },
}


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, default=str) + "\n", encoding="utf-8")


def setup() -> Any:
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    if not COMP_DIR.exists():
        raise RuntimeError(f"Missing competition SDK: {COMP_DIR}")
    for model_name in REQUESTED_MODELS:
        model_path = MODEL_CONFIG[model_name]["path"]
        if not model_path.exists():
            raise RuntimeError(f"Missing {model_name} model: {model_path}")

    gpu = subprocess.run(["nvidia-smi"], check=False, capture_output=True, text=True)
    if gpu.returncode != 0:
        raise RuntimeError("This evaluator requires a Kaggle NVIDIA GPU")

    attack_bytes = importlib.import_module("base64").b64decode(ATTACK_PAYLOAD_B64)
    if hashlib.sha256(attack_bytes).hexdigest() != ATTACK_SHA256:
        raise RuntimeError("Injected attack SHA-256 mismatch")
    ATTACK_PATH.write_bytes(attack_bytes)

    sys.path.insert(0, str(COMP_DIR))
    os.environ["PYTHONUTF8"] = "1"
    for name, model in MODEL_CONFIG.items():
        os.environ[f"{name.upper()}_MODEL_PATH"] = str(model["path"])

    if importlib.util.find_spec("llama_cpp") is None:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "-q",
                "--upgrade",
                "--no-cache-dir",
                "llama-cpp-python",
                "--extra-index-url",
                "https://abetlen.github.io/llama-cpp-python/whl/cu124",
            ],
            check=True,
        )
    return importlib.import_module("llama_cpp")


def load_attack_class() -> type[Any]:
    spec = importlib.util.spec_from_file_location("submitted_attack", ATTACK_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load injected attack.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.AttackAlgorithm


def unload_model(server: Any, label: str) -> None:
    if server is not None:
        try:
            server.unload()
        except Exception as error:
            print(f"{label} unload error: {error!r}")
    gc.collect()
    try:
        import torch

        torch.cuda.empty_cache()
    except Exception:
        pass


def finding_digest(findings: list[dict[str, Any]]) -> dict[str, Any]:
    predicates: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    cells: set[str] = set()
    prompts: list[list[str]] = []
    for finding in findings:
        prompts.append(list(finding.get("user_messages", [])))
        for predicate in finding.get("predicates", []):
            predicates[str(predicate.get("predicate", "unknown"))] += 1
            severities[str(predicate.get("severity", "unknown"))] += 1
        for event in finding.get("trace", {}).get("tool_events", []):
            if event.get("ok"):
                tools[str(event.get("name", "unknown"))] += 1
        signature = finding.get("score_cell_signature") or finding.get("cell_signature") or {}
        if signature.get("hash"):
            cells.add(str(signature["hash"]))
    return {
        "predicate_counts": dict(predicates),
        "severity_counts": dict(severities),
        "successful_tool_counts": dict(tools),
        "score_cell_hashes": sorted(cells),
        "successful_prompt_chains": prompts,
    }


def evaluate_model(
    attack_class: type[Any], model_name: str, gateway_defaults: Any
) -> dict[str, Any]:
    from aicomp_sdk.core.env.api import EnvSelection
    from aicomp_sdk.evaluation.diagnostics import EvaluatorVerbosity, RunDiagnostics
    from aicomp_sdk.evaluation.runner import evaluate_redteam
    from kaggle_evaluation.jed_attack_134815 import gemma_model_server, gpt_oss_model_server
    from kaggle_evaluation.jed_attack_134815.gguf_model_server import GgufModelServer

    module = gpt_oss_model_server if model_name == "gpt_oss" else gemma_model_server
    server = None
    started = time.time()
    try:
        server = GgufModelServer(module.SPEC)
        server.load_model()
        with RunDiagnostics(
            EvaluatorVerbosity.DEBUG,
            transcript_file=ARTIFACTS_DIR / f"{model_name}_transcript.log",
            event_log_file=ARTIFACTS_DIR / f"{model_name}_framework.jsonl",
            agent_debug_file=ARTIFACTS_DIR / f"{model_name}_agent_debug.jsonl",
        ) as diagnostics:
            execution = evaluate_redteam(
                attack_class,
                budget_s=REQUESTED_BUDGET_S,
                agent_factory=lambda: server._load_agent(),
                agent_label=f"{model_name}_gguf",
                env_selection=EnvSelection.GYM,
                fixtures_dir=COMP_DIR / "aicomp_sdk" / "fixtures",
                diagnostics=diagnostics,
                attack_env_seed=gateway_defaults.ATTACK_SEED,
            )
        attack = execution.attack
        findings = list(attack.findings)
        summary = {
            "status": "complete",
            "model": model_name,
            "model_path": str(MODEL_CONFIG[model_name]["path"]),
            "score_normalized_0_to_1000": attack.score,
            "score_raw": attack.score_raw,
            "findings_count": attack.findings_count,
            "unique_cells": attack.unique_cells,
            "unique_canonical_cells": attack.unique_canonical_cells,
            "evaluation_time_s": attack.time_taken,
            "wall_time_s": time.time() - started,
            "guardrail_id": attack.guardrail_id,
            "guardrail_version": attack.guardrail_version,
            "finding_digest": finding_digest(findings),
        }
        write_json(ARTIFACTS_DIR / f"{model_name}_summary.json", summary)
        write_json(ARTIFACTS_DIR / f"{model_name}_findings.json", findings)
        return summary
    finally:
        unload_model(server, model_name)


def main() -> None:
    setup()
    from kaggle_evaluation.jed_attack_134815 import jed_attack_gateway as gateway_defaults

    started_at = datetime.now(timezone.utc)
    started = time.time()
    summaries: dict[str, Any] = {}
    failures: dict[str, Any] = {}

    try:
        attack_class = load_attack_class()
    except Exception as error:
        failures["attack_import"] = {
            "error_type": type(error).__name__,
            "error": str(error),
            "traceback": traceback.format_exc(),
        }
        attack_class = None

    if attack_class is not None:
        for model_name in REQUESTED_MODELS:
            try:
                summaries[model_name] = evaluate_model(attack_class, model_name, gateway_defaults)
            except Exception as error:
                failure = {
                    "status": "failed",
                    "model": model_name,
                    "error_type": type(error).__name__,
                    "error": str(error),
                    "traceback": traceback.format_exc(),
                }
                summaries[model_name] = failure
                failures[model_name] = failure
                write_json(ARTIFACTS_DIR / f"{model_name}_summary.json", failure)

    scores = [
        value["score_normalized_0_to_1000"]
        for value in summaries.values()
        if value.get("status") == "complete"
    ]
    combined = {
        "status": "failed" if failures else "complete",
        "profile": RUN_PROFILE,
        "attack_sha256": ATTACK_SHA256,
        "requested_models": list(REQUESTED_MODELS),
        "budget_s_per_model": REQUESTED_BUDGET_S,
        "attack_seed": gateway_defaults.ATTACK_SEED,
        "max_tool_hops": gateway_defaults.DEFAULT_MAX_TOOL_HOPS,
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "wall_time_s": time.time() - started,
        "models": summaries,
        "failures": failures,
        "mean_score": sum(scores) / len(scores) if scores else None,
    }
    write_json(ARTIFACTS_DIR / "validation_summary.json", combined)
    print(json.dumps(combined, indent=2, default=str))
    if failures:
        raise RuntimeError(f"Validation failed for: {', '.join(failures)}")


if __name__ == "__main__":
    main()
