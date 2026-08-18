from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path

import pytest

from jed_validator.experiments import build_report, history, latest_report
from jed_validator.kaggle_runner import (
    CommandResult,
    KaggleRunnerError,
    ensure_kaggle_access,
    ensure_kernel_idle,
    kernel_metadata,
    load_dotenv,
    resolve_kernel,
    run_remote_validation,
    stage_kernel,
    validate_attack_source,
)

ATTACK_SOURCE = """\
class AttackAlgorithm:
    def run(self, env, config):
        return []
"""


@pytest.fixture
def attack_file(tmp_path: Path) -> Path:
    path = tmp_path / "attack.py"
    path.write_text(ATTACK_SOURCE, encoding="utf-8")
    return path


@pytest.fixture
def evaluator_path() -> Path:
    return Path(__file__).parents[1] / "scripts" / "remote_validation.py"


class FakeKaggleCli:
    def __init__(
        self,
        *,
        status_results: list[CommandResult] | None = None,
        push_result: CommandResult | None = None,
        auth_result: CommandResult | None = None,
        output_result: CommandResult | None = None,
        live_code: int = 0,
        summary: dict[str, object] | None = None,
    ) -> None:
        self.status_results = list(status_results or [CommandResult(1, "", "404 not found")])
        self.push_result = push_result or CommandResult(
            0, "Kernel version 7 successfully pushed", ""
        )
        self.auth_result = auth_result or CommandResult(0, "ok", "")
        self.output_result = output_result or CommandResult(0, "downloaded", "")
        self.live_code = live_code
        self.summary = summary or {
            "status": "complete",
            "profile": "screen",
            "attack_sha256": None,
            "requested_models": ["gpt_oss"],
            "budget_s_per_model": 60.0,
            "models": {
                "gpt_oss": {
                    "status": "complete",
                    "score_normalized_0_to_1000": 0.27,
                    "score_raw": 54.0,
                    "findings_count": 2,
                    "unique_canonical_cells": 2,
                    "finding_digest": {
                        "predicate_counts": {"EXFILTRATION": 2},
                        "successful_prompt_chains": [["prompt one"]],
                    },
                }
            },
            "mean_score": 0.27,
            "failures": {},
        }
        self.calls: list[tuple[str, ...]] = []

    def capture(self, *arguments: str) -> CommandResult:
        self.calls.append(arguments)
        if arguments[:2] == ("kernels", "list"):
            return self.auth_result
        if arguments[:2] == ("kernels", "status"):
            if len(self.status_results) > 1:
                return self.status_results.pop(0)
            return self.status_results[0]
        if arguments[:2] == ("kernels", "push"):
            staged = Path(arguments[arguments.index("--path") + 1])
            source = (staged / "remote_validation.py").read_text(encoding="utf-8")
            match = re.search(r"^ATTACK_SHA256 = '([0-9a-f]+)'$", source, re.MULTILINE)
            assert match is not None
            self.summary["attack_sha256"] = match.group(1)
            return self.push_result
        if arguments[:2] == ("kernels", "output"):
            if self.output_result.returncode == 0:
                destination = Path(arguments[arguments.index("--path") + 1])
                artifacts = destination / "artifacts"
                artifacts.mkdir(parents=True, exist_ok=True)
                (artifacts / "validation_summary.json").write_text(
                    json.dumps(self.summary), encoding="utf-8"
                )
            return self.output_result
        raise AssertionError(f"Unexpected Kaggle command: {arguments}")

    def live(self, *arguments: str) -> int:
        self.calls.append(arguments)
        return self.live_code


def test_resolve_kernel_precedence_and_default() -> None:
    env = {"JED_KAGGLE_KERNEL": "env-owner/env-kernel", "KAGGLE_USERNAME": "owner"}
    assert resolve_kernel("arg-owner/arg-kernel", env) == "arg-owner/arg-kernel"
    assert resolve_kernel(None, env) == "env-owner/env-kernel"
    assert resolve_kernel(None, {"KAGGLE_USERNAME": "owner"}) == "owner/aas-remote-validation"


def test_dotenv_loads_only_approved_missing_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "KAGGLE_USERNAME=owner\nKAGGLE_API_TOKEN='secret-token'\nUNRELATED=nope\n",
        encoding="utf-8",
    )
    for key in ("KAGGLE_USERNAME", "KAGGLE_API_TOKEN", "UNRELATED"):
        monkeypatch.delenv(key, raising=False)
    load_dotenv(dotenv)
    assert os.environ["KAGGLE_USERNAME"] == "owner"
    assert os.environ["KAGGLE_API_TOKEN"] == "secret-token"
    assert "UNRELATED" not in os.environ


@pytest.mark.parametrize("source", ["x = 1\n", "class AttackAlgorithm: pass\n", "bad python !"])
def test_attack_validation_rejects_invalid_contract(tmp_path: Path, source: str) -> None:
    path = tmp_path / "attack.py"
    path.write_text(source, encoding="utf-8")
    with pytest.raises(KaggleRunnerError):
        validate_attack_source(path)


def test_stage_kernel_embeds_attack_config_and_preserves_sources(
    tmp_path: Path, evaluator_path: Path, attack_file: Path
) -> None:
    evaluator_before = evaluator_path.read_bytes()
    attack_before = attack_file.read_bytes()
    staged = stage_kernel(
        evaluator_path,
        attack_file,
        "owner/aas-remote-validation",
        "NvidiaTeslaT4",
        tmp_path / "stage",
        models=("gpt_oss",),
        budget_s=600,
        profile="test-screen",
    )
    assert evaluator_path.read_bytes() == evaluator_before
    assert attack_file.read_bytes() == attack_before
    generated = staged.code_path.read_text(encoding="utf-8")
    payload = re.search(r"^ATTACK_PAYLOAD_B64 = '([^']+)'$", generated, re.MULTILINE)
    assert payload is not None
    assert base64.b64decode(payload.group(1)) == attack_before
    assert "REQUESTED_MODELS = ('gpt_oss',)" in generated
    assert "REQUESTED_BUDGET_S = 600.0" in generated
    assert "RUN_PROFILE = 'test-screen'" in generated
    compile(generated, str(staged.code_path), "exec")
    metadata = json.loads(staged.metadata_path.read_text(encoding="utf-8"))
    assert metadata == kernel_metadata(
        "owner/aas-remote-validation",
        "remote_validation.py",
        "NvidiaTeslaT4",
        ("gpt_oss",),
    )
    assert metadata["kernel_type"] == "script"
    assert len(metadata["model_sources"]) == 1
    assert "KAGGLE_API_TOKEN" not in generated
    assert "kaggle.json" not in generated


def test_stage_rejects_unknown_model(
    tmp_path: Path, evaluator_path: Path, attack_file: Path
) -> None:
    with pytest.raises(KaggleRunnerError, match="Unknown validation model"):
        stage_kernel(
            evaluator_path,
            attack_file,
            "owner/aas-remote-validation",
            "NvidiaTeslaT4",
            tmp_path,
            models=("unknown",),
        )


def test_auth_and_active_kernel_errors() -> None:
    with pytest.raises(KaggleRunnerError, match="authentication"):
        ensure_kaggle_access(FakeKaggleCli(auth_result=CommandResult(1, "", "unauthorized")))
    active = FakeKaggleCli(status_results=[CommandResult(0, "RUNNING", "")])
    with pytest.raises(KaggleRunnerError, match="already has"):
        ensure_kernel_idle(active, "owner/aas-remote-validation")


def test_successful_run_uses_slug_for_logs_and_version_for_output(
    tmp_path: Path, evaluator_path: Path, attack_file: Path
) -> None:
    cli = FakeKaggleCli(
        status_results=[CommandResult(1, "", "404"), CommandResult(0, "COMPLETE", "")]
    )
    result = run_remote_validation(
        attack_file,
        kernel="owner/aas-remote-validation",
        results_root=tmp_path / "results",
        evaluator_path=evaluator_path,
        cli=cli,
        models=("gpt_oss",),
        budget_s=60,
        profile="screen",
    )
    assert result.version == 7
    assert result.summary is not None and result.summary["mean_score"] == 0.27
    assert ("kernels", "logs", "--follow", "owner/aas-remote-validation") in cli.calls
    assert ("kernels", "status", "owner/aas-remote-validation") in cli.calls
    assert any(
        call[:3] == ("kernels", "output", "owner/aas-remote-validation/7") for call in cli.calls
    )


def test_log_disconnect_falls_back_to_polling(
    tmp_path: Path, evaluator_path: Path, attack_file: Path
) -> None:
    cli = FakeKaggleCli(
        live_code=1,
        status_results=[
            CommandResult(1, "", "404"),
            CommandResult(0, "RUNNING", ""),
            CommandResult(0, "COMPLETE", ""),
        ],
    )
    result = run_remote_validation(
        attack_file,
        kernel="owner/aas-remote-validation",
        results_root=tmp_path / "results",
        evaluator_path=evaluator_path,
        cli=cli,
        poll_interval_s=1,
        models=("gpt_oss",),
        budget_s=60,
    )
    assert result.summary is not None


def test_sha_mismatch_is_rejected(tmp_path: Path, evaluator_path: Path, attack_file: Path) -> None:
    cli = FakeKaggleCli(
        status_results=[CommandResult(1, "", "404"), CommandResult(0, "COMPLETE", "")]
    )
    cli.summary["attack_sha256"] = "will-be-overwritten-during-push"
    original_capture = cli.capture

    def capture(*arguments: str) -> CommandResult:
        result = original_capture(*arguments)
        if arguments[:2] == ("kernels", "output"):
            destination = Path(arguments[arguments.index("--path") + 1])
            summary_path = destination / "artifacts" / "validation_summary.json"
            value = json.loads(summary_path.read_text())
            value["attack_sha256"] = "wrong"
            summary_path.write_text(json.dumps(value), encoding="utf-8")
        return result

    cli.capture = capture  # type: ignore[method-assign]
    with pytest.raises(KaggleRunnerError, match="do not match"):
        run_remote_validation(
            attack_file,
            kernel="owner/aas-remote-validation",
            results_root=tmp_path / "results",
            evaluator_path=evaluator_path,
            cli=cli,
            models=("gpt_oss",),
            budget_s=60,
        )


def test_report_and_history_surface_optimization_feedback(
    tmp_path: Path, evaluator_path: Path, attack_file: Path
) -> None:
    cli = FakeKaggleCli(
        status_results=[CommandResult(1, "", "404"), CommandResult(0, "COMPLETE", "")]
    )
    result = run_remote_validation(
        attack_file,
        kernel="owner/aas-remote-validation",
        results_root=tmp_path / "results",
        evaluator_path=evaluator_path,
        cli=cli,
        models=("gpt_oss",),
        budget_s=60,
    )
    report = latest_report(result.result_directory)
    assert report["models"][0]["predicates"] == {"EXFILTRATION": 2}
    rows = history(tmp_path / "results")
    assert rows[0]["mean_score"] == 0.27
    direct = build_report(result.summary or {}, result.result_directory)
    assert direct["profile"] == "screen"
