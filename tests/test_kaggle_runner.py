from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from jed_validator import kaggle_runner
from jed_validator.kaggle_runner import (
    ATTACK_CELL_TAG,
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
def notebook_path() -> Path:
    return Path(__file__).parents[1] / "scripts" / "aas-local-validation.ipynb"


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
            "attack_sha256": None,
            "models": {
                "gpt_oss": {
                    "status": "complete",
                    "score_normalized_0_to_1000": 0.27,
                },
                "gemma": {
                    "status": "complete",
                    "score_normalized_0_to_1000": 0.24,
                },
            },
            "local_public_mean": 0.255,
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
            staged_directory = Path(arguments[arguments.index("--path") + 1])
            notebook = next(staged_directory.glob("*.ipynb"))
            generated = json.loads(notebook.read_text(encoding="utf-8"))
            injected = next(
                cell
                for cell in generated["cells"]
                if ATTACK_CELL_TAG in cell.get("metadata", {}).get("tags", [])
            )
            digest_line = next(
                line for line in injected["source"] if line.startswith("ATTACK_SHA256 = ")
            )
            self.summary["attack_sha256"] = digest_line.split("=", 1)[1].strip().strip("'")
            return self.push_result
        if arguments[:2] == ("kernels", "output"):
            if self.output_result.returncode == 0:
                destination = Path(arguments[arguments.index("--path") + 1])
                artifact_dir = destination / "artifacts"
                artifact_dir.mkdir(parents=True, exist_ok=True)
                (artifact_dir / "validation_summary.json").write_text(
                    json.dumps(self.summary), encoding="utf-8"
                )
            return self.output_result
        raise AssertionError(f"Unexpected Kaggle command: {arguments}")

    def live(self, *arguments: str) -> int:
        self.calls.append(arguments)
        return self.live_code


def test_resolve_kernel_precedence_and_default() -> None:
    env = {
        "JED_KAGGLE_KERNEL": "env-owner/env-kernel",
        "KAGGLE_USERNAME": "fallback-owner",
    }
    assert resolve_kernel("flag-owner/flag-kernel", env) == "flag-owner/flag-kernel"
    assert resolve_kernel(environment=env) == "env-owner/env-kernel"
    assert resolve_kernel(environment={"KAGGLE_USERNAME": "owner"}) == (
        "owner/aas-remote-validation"
    )


def test_resolve_kernel_requires_configuration() -> None:
    with pytest.raises(KaggleRunnerError, match="JED_KAGGLE_KERNEL"):
        resolve_kernel(environment={})
    with pytest.raises(KaggleRunnerError, match="owner/kernel-slug"):
        resolve_kernel("Owner/not_ok", {})


def test_dotenv_loads_only_approved_keys_without_overriding_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "KAGGLE_USERNAME=dotenv-user\n"
        "KAGGLE_API_TOKEN='secret-token'\n"
        "JED_KAGGLE_KERNEL=dotenv-user/remote-validation\n"
        "UNRELATED_SETTING=do-not-load\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("KAGGLE_USERNAME", "shell-user")
    monkeypatch.delenv("KAGGLE_API_TOKEN", raising=False)
    monkeypatch.delenv("JED_KAGGLE_KERNEL", raising=False)
    monkeypatch.delenv("UNRELATED_SETTING", raising=False)

    load_dotenv(dotenv)

    assert os.environ["KAGGLE_USERNAME"] == "shell-user"
    assert os.environ["KAGGLE_API_TOKEN"] == "secret-token"
    assert os.environ["JED_KAGGLE_KERNEL"] == "dotenv-user/remote-validation"
    assert "UNRELATED_SETTING" not in os.environ


def test_attack_preflight_rejects_syntax_and_missing_run(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.py"
    invalid.write_text("class AttackAlgorithm(:\n", encoding="utf-8")
    with pytest.raises(KaggleRunnerError, match="invalid Python syntax"):
        validate_attack_source(invalid)

    missing_run = tmp_path / "missing_run.py"
    missing_run.write_text("class AttackAlgorithm:\n    pass\n", encoding="utf-8")
    with pytest.raises(KaggleRunnerError, match="define a `run` method"):
        validate_attack_source(missing_run)


def test_stage_kernel_injects_exact_attack_and_does_not_mutate_sources(
    tmp_path: Path,
    notebook_path: Path,
    attack_file: Path,
) -> None:
    notebook_before = notebook_path.read_bytes()
    attack_before = attack_file.read_bytes()
    staged = stage_kernel(
        notebook_path,
        attack_file,
        "owner/aas-remote-validation",
        "NvidiaTeslaT4",
        tmp_path / "stage",
    )

    assert notebook_path.read_bytes() == notebook_before
    assert attack_file.read_bytes() == attack_before
    generated = json.loads(staged.notebook_path.read_text(encoding="utf-8"))
    cells = [
        cell
        for cell in generated["cells"]
        if ATTACK_CELL_TAG in cell.get("metadata", {}).get("tags", [])
    ]
    assert len(cells) == 1
    decoded_attack = tmp_path / "decoded.py"
    exec("".join(cells[0]["source"]), {"ATTACK_PATH": decoded_attack})
    assert decoded_attack.read_bytes() == attack_before
    assert all(
        cell.get("execution_count") is None and cell.get("outputs") == []
        for cell in generated["cells"]
        if cell["cell_type"] == "code"
    )

    metadata = json.loads(staged.metadata_path.read_text(encoding="utf-8"))
    assert metadata == kernel_metadata(
        "owner/aas-remote-validation",
        notebook_path.name,
        "NvidiaTeslaT4",
    )
    uploaded_text = staged.notebook_path.read_text(encoding="utf-8")
    assert "KAGGLE_API_TOKEN" not in uploaded_text
    assert "kaggle.json" not in uploaded_text


def test_stage_kernel_requires_exactly_one_injection_cell(
    tmp_path: Path,
    notebook_path: Path,
    attack_file: Path,
) -> None:
    notebook = json.loads(notebook_path.read_text(encoding="utf-8"))
    for cell in notebook["cells"]:
        cell.get("metadata", {}).pop("tags", None)
    broken = tmp_path / "broken.ipynb"
    broken.write_text(json.dumps(notebook), encoding="utf-8")
    with pytest.raises(KaggleRunnerError, match="exactly one"):
        stage_kernel(
            broken,
            attack_file,
            "owner/aas-remote-validation",
            "NvidiaTeslaT4",
            tmp_path / "stage",
        )


def test_access_and_concurrency_failures_are_clear() -> None:
    unauthenticated = FakeKaggleCli(auth_result=CommandResult(1, "", "401 Unauthorized"))
    with pytest.raises(KaggleRunnerError, match="authentication check.*Unauthorized"):
        ensure_kaggle_access(unauthenticated)

    active = FakeKaggleCli(status_results=[CommandResult(0, "KernelWorkerStatus.RUNNING", "")])
    with pytest.raises(KaggleRunnerError, match="already has a queued or running job"):
        ensure_kernel_idle(active, "owner/aas-remote-validation")

    failed = FakeKaggleCli(
        status_results=[
            CommandResult(
                0,
                'owner/kernel has status "error"\nFailure message: "failed while running model"',
                "",
            )
        ]
    )
    ensure_kernel_idle(failed, "owner/aas-remote-validation")


def test_first_run_accepts_kaggle_missing_kernel_permission_response() -> None:
    missing = FakeKaggleCli(
        status_results=[
            CommandResult(
                1,
                "",
                "Cannot access kernel 'owner/aas-remote-validation' "
                "(Permission 'kernels.get' was denied). The most likely cause is a wrong "
                "kernel slug.",
            )
        ]
    )
    ensure_kernel_idle(missing, "owner/aas-remote-validation")


def test_successful_remote_run_uses_versioned_output_and_writes_manifest(
    tmp_path: Path,
    notebook_path: Path,
    attack_file: Path,
) -> None:
    cli = FakeKaggleCli(
        status_results=[
            CommandResult(1, "", "404 not found"),
            CommandResult(0, "KernelWorkerStatus.COMPLETE", ""),
        ]
    )
    result = run_remote_validation(
        attack_file,
        kernel="owner/aas-remote-validation",
        results_root=tmp_path / "results",
        notebook_path=notebook_path,
        cli=cli,
    )

    assert result.version == 7
    assert result.summary is not None
    assert result.summary["local_public_mean"] == 0.255
    assert (result.result_directory / "local_run.json").is_file()
    assert ("kernels", "logs", "--follow", "owner/aas-remote-validation") in cli.calls
    assert ("kernels", "status", "owner/aas-remote-validation") in cli.calls
    assert any(
        call[:3] == ("kernels", "output", "owner/aas-remote-validation/7") for call in cli.calls
    )


def test_log_disconnect_falls_back_to_status_polling(
    tmp_path: Path,
    notebook_path: Path,
    attack_file: Path,
) -> None:
    cli = FakeKaggleCli(
        live_code=1,
        status_results=[
            CommandResult(1, "", "404 not found"),
            CommandResult(0, "RUNNING", ""),
            CommandResult(0, "COMPLETE", ""),
        ],
    )
    result = run_remote_validation(
        attack_file,
        kernel="owner/aas-remote-validation",
        results_root=tmp_path / "results",
        notebook_path=notebook_path,
        cli=cli,
        poll_interval_s=1,
    )
    assert result.summary is not None


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("GPU quota exhausted", "quota exhausted"),
        ("Model source is not accessible", "not accessible"),
    ],
)
def test_submission_errors_surface_kaggle_details(
    tmp_path: Path,
    notebook_path: Path,
    attack_file: Path,
    message: str,
    expected: str,
) -> None:
    cli = FakeKaggleCli(push_result=CommandResult(1, "", message))
    with pytest.raises(KaggleRunnerError, match=expected):
        run_remote_validation(
            attack_file,
            kernel="owner/aas-remote-validation",
            results_root=tmp_path / "results",
            notebook_path=notebook_path,
            cli=cli,
        )


def test_failed_remote_run_downloads_partial_artifacts(
    tmp_path: Path,
    notebook_path: Path,
    attack_file: Path,
) -> None:
    cli = FakeKaggleCli(
        status_results=[
            CommandResult(1, "", "404 not found"),
            CommandResult(0, "KernelWorkerStatus.ERROR", ""),
        ],
        summary={"status": "failed", "models": {}, "failures": {"gemma": {}}},
    )
    with pytest.raises(KaggleRunnerError, match="Remote validation failed"):
        run_remote_validation(
            attack_file,
            kernel="owner/aas-remote-validation",
            results_root=tmp_path / "results",
            notebook_path=notebook_path,
            cli=cli,
        )
    assert list((tmp_path / "results").rglob("validation_summary.json"))
    assert list((tmp_path / "results").rglob("local_run.json"))


def test_download_failure_after_success_is_reported(
    tmp_path: Path,
    notebook_path: Path,
    attack_file: Path,
) -> None:
    cli = FakeKaggleCli(
        status_results=[
            CommandResult(1, "", "404 not found"),
            CommandResult(0, "COMPLETE", ""),
        ],
        output_result=CommandResult(1, "", "download unavailable"),
    )
    with pytest.raises(KaggleRunnerError, match="artifact download.*unavailable"):
        run_remote_validation(
            attack_file,
            kernel="owner/aas-remote-validation",
            results_root=tmp_path / "results",
            notebook_path=notebook_path,
            cli=cli,
        )


def test_missing_version_is_rejected_after_submission(
    tmp_path: Path,
    notebook_path: Path,
    attack_file: Path,
) -> None:
    cli = FakeKaggleCli(push_result=CommandResult(0, "Kernel pushed", ""))
    with pytest.raises(KaggleRunnerError, match="did not report its version number"):
        run_remote_validation(
            attack_file,
            kernel="owner/aas-remote-validation",
            results_root=tmp_path / "results",
            notebook_path=notebook_path,
            cli=cli,
        )


def test_stale_download_is_rejected_by_attack_hash(
    tmp_path: Path,
    notebook_path: Path,
    attack_file: Path,
) -> None:
    cli = FakeKaggleCli(
        status_results=[
            CommandResult(1, "", "404 not found"),
            CommandResult(0, "COMPLETE", ""),
        ]
    )
    original_capture = cli.capture

    def capture_with_stale_output(*arguments: str) -> CommandResult:
        result = original_capture(*arguments)
        if arguments[:2] == ("kernels", "output"):
            destination = Path(arguments[arguments.index("--path") + 1])
            summary_path = destination / "artifacts" / "validation_summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["attack_sha256"] = "0" * 64
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
        return result

    cli.capture = capture_with_stale_output  # type: ignore[method-assign]
    with pytest.raises(KaggleRunnerError, match="do not match the submitted attack"):
        run_remote_validation(
            attack_file,
            kernel="owner/aas-remote-validation",
            results_root=tmp_path / "results",
            notebook_path=notebook_path,
            cli=cli,
        )


def test_polling_timeout_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    cli = FakeKaggleCli(status_results=[CommandResult(0, "RUNNING", "")])
    times = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr("jed_validator.kaggle_runner.time.monotonic", lambda: next(times))
    monkeypatch.setattr("jed_validator.kaggle_runner.time.sleep", lambda _: None)
    with pytest.raises(KaggleRunnerError, match="Timed out"):
        kaggle_runner._wait_for_terminal_status(  # noqa: SLF001
            cli,
            "owner/aas-remote-validation/7",
            timeout_s=1,
            poll_interval_s=1,
        )
