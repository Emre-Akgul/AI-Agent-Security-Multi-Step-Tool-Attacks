"""Stage and run competition-matched validation on a Kaggle GPU."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

MIN_KAGGLE_VERSION = (2, 2, 3)
DEFAULT_ACCELERATOR = "NvidiaTeslaT4"
DEFAULT_TIMEOUT_S = 12 * 60 * 60
DEFAULT_POLL_INTERVAL_S = 15
DEFAULT_KERNEL_SLUG = "aas-remote-validation"
COMPETITION_SOURCE = "ai-agent-security-multi-step-tool-attacks"
MODEL_SOURCES = {
    "gpt_oss": "llkh0a/gpt-oss-20b-gguf/pytorch/default/1",
    "gemma": "llkh0a/gemma-4-26b-a4b-it-ud-q4-k-m-gguf/pytorch/default/1",
}
DEFAULT_MODELS = ("gpt_oss", "gemma")
OFFICIAL_BUDGET_S = 8750.0
RUN_CONFIG_MARKER = "# __JED_RUN_CONFIGURATION__"
DOTENV_KEYS = frozenset(
    {
        "JED_KAGGLE_BIN",
        "JED_KAGGLE_KERNEL",
        "KAGGLE_API_TOKEN",
        "KAGGLE_KEY",
        "KAGGLE_USERNAME",
    }
)


class KaggleRunnerError(RuntimeError):
    """Raised when local preparation or a Kaggle operation fails."""


@dataclass(frozen=True)
class CommandResult:
    """Captured result from a Kaggle CLI invocation."""

    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class StagedKernel:
    """Paths and identity for one generated Kaggle kernel submission."""

    directory: Path
    code_path: Path
    metadata_path: Path
    attack_sha256: str


@dataclass(frozen=True)
class KaggleRunResult:
    """Downloaded result of a completed remote validation run."""

    kernel: str
    version: int | None
    attack_sha256: str
    result_directory: Path
    summary: Mapping[str, Any] | None


class KaggleCli:
    """Small subprocess adapter around the official Kaggle CLI."""

    def __init__(self, command: Sequence[str] | None = None) -> None:
        self.command = list(command or resolve_kaggle_command())

    def capture(self, *arguments: str) -> CommandResult:
        completed = subprocess.run(
            [*self.command, *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)

    def live(self, *arguments: str) -> int:
        completed = subprocess.run([*self.command, *arguments], check=False)
        return completed.returncode


class KaggleClient(Protocol):
    """Command surface used by orchestration and supplied by tests."""

    def capture(self, *arguments: str) -> CommandResult: ...

    def live(self, *arguments: str) -> int: ...


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_evaluator_path() -> Path:
    """Return the maintainable Python evaluator used to build a Kaggle script."""

    return _repository_root() / "scripts" / "remote_validation.py"


def load_dotenv(path: Path | None = None) -> None:
    """Load approved Kaggle settings without executing shell syntax.

    Existing process variables always win. Other names in the file are ignored so
    validation cannot unexpectedly alter the surrounding development environment.
    """

    dotenv_path = path or (_repository_root() / ".env")
    if not dotenv_path.is_file():
        return
    try:
        lines = dotenv_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise KaggleRunnerError(f"Cannot read {dotenv_path}: {error}") from error

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").strip()
        key, separator, raw_value = line.partition("=")
        key = key.strip()
        if not separator or key not in DOTENV_KEYS:
            continue
        value = raw_value.strip()
        if value[:1] in {"'", '"'}:
            try:
                parsed = ast.literal_eval(value)
            except (SyntaxError, ValueError) as error:
                raise KaggleRunnerError(
                    f"Invalid quoted value for {key} in {dotenv_path}:{line_number}"
                ) from error
            if not isinstance(parsed, str):
                raise KaggleRunnerError(
                    f"Expected a string value for {key} in {dotenv_path}:{line_number}"
                )
            value = parsed
        os.environ.setdefault(key, value)


def resolve_kernel(
    explicit: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> str:
    """Resolve and validate the writable Kaggle kernel identifier."""

    if environment is None:
        load_dotenv()
    env = os.environ if environment is None else environment
    kernel = explicit or env.get("JED_KAGGLE_KERNEL")
    if kernel is None and env.get("KAGGLE_USERNAME"):
        kernel = f"{env['KAGGLE_USERNAME']}/{DEFAULT_KERNEL_SLUG}"
    if kernel is None:
        raise KaggleRunnerError(
            "Kaggle kernel is not configured. Run `kaggle auth login`, then set "
            "`JED_KAGGLE_KERNEL=YOUR_USERNAME/aas-remote-validation` or pass "
            "`--kernel YOUR_USERNAME/aas-remote-validation`."
        )
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]{4,}", kernel):
        raise KaggleRunnerError(
            "Kaggle kernel must use the form owner/kernel-slug with lowercase letters, "
            "digits, and hyphens."
        )
    return kernel


def attack_sha256(path: Path) -> str:
    """Hash an attack file so remote and local results can be matched."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_attack_source(path: Path) -> str:
    """Perform a cheap local syntax and entry-point check."""

    if not path.is_file():
        raise KaggleRunnerError(f"Attack file does not exist: {path}")
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise KaggleRunnerError(f"Cannot read attack file {path}: {error}") from error
    try:
        tree = ast.parse(source, filename=str(path))
        compile(tree, str(path), "exec")
    except SyntaxError as error:
        raise KaggleRunnerError(f"Attack file has invalid Python syntax: {error}") from error
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    attack_class = next((node for node in classes if node.name == "AttackAlgorithm"), None)
    if attack_class is None:
        raise KaggleRunnerError("attack.py must define a top-level `AttackAlgorithm` class")
    if not any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run"
        for node in attack_class.body
    ):
        raise KaggleRunnerError("AttackAlgorithm must define a `run` method")
    return source


def _injection_source(
    payload: bytes,
    digest: str,
    models: Sequence[str],
    budget_s: float,
    profile: str,
) -> str:
    encoded = base64.b64encode(payload).decode("ascii")
    return "\n".join(
        (
            "# Generated by jed-validate; this block exists only in the staged script.",
            f"ATTACK_SHA256 = {digest!r}",
            f"ATTACK_PAYLOAD_B64 = {encoded!r}",
            f"REQUESTED_MODELS = {tuple(models)!r}",
            f"REQUESTED_BUDGET_S = {float(budget_s)!r}",
            f"RUN_PROFILE = {profile!r}",
        )
    )


def kernel_metadata(
    kernel: str,
    code_name: str,
    accelerator: str,
    models: Sequence[str] = DEFAULT_MODELS,
) -> dict[str, Any]:
    """Build the metadata consumed by ``kaggle kernels push``."""

    slug = kernel.split("/", 1)[1]
    return {
        "id": kernel,
        "title": slug.replace("-", " ").title(),
        "code_file": code_name,
        "language": "python",
        "kernel_type": "script",
        "is_private": True,
        "enable_gpu": True,
        "enable_internet": True,
        "machine_shape": accelerator,
        "dataset_sources": [],
        "competition_sources": [COMPETITION_SOURCE],
        "kernel_sources": [],
        "model_sources": [MODEL_SOURCES[model] for model in models],
    }


def stage_kernel(
    evaluator_path: Path,
    attack_path: Path,
    kernel: str,
    accelerator: str,
    destination: Path,
    *,
    models: Sequence[str] = DEFAULT_MODELS,
    budget_s: float = OFFICIAL_BUDGET_S,
    profile: str = "full",
) -> StagedKernel:
    """Create one uploadable script without modifying either source file."""

    validate_attack_source(attack_path)
    payload = attack_path.read_bytes()
    try:
        evaluator = evaluator_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise KaggleRunnerError(
            f"Cannot read remote evaluator {evaluator_path}: {error}"
        ) from error
    if evaluator.count(RUN_CONFIG_MARKER) != 1:
        raise KaggleRunnerError(
            f"Remote evaluator must contain exactly one `{RUN_CONFIG_MARKER}` marker"
        )
    selected_models = tuple(models)
    if not selected_models or len(set(selected_models)) != len(selected_models):
        raise KaggleRunnerError("models must be a non-empty sequence without duplicates")
    unknown = set(selected_models) - MODEL_SOURCES.keys()
    if unknown:
        raise KaggleRunnerError(f"Unknown validation model(s): {', '.join(sorted(unknown))}")
    if budget_s <= 0:
        raise KaggleRunnerError("budget must be positive")

    digest = hashlib.sha256(payload).hexdigest()
    generated = evaluator.replace(
        RUN_CONFIG_MARKER,
        _injection_source(payload, digest, selected_models, budget_s, profile),
    )

    destination.mkdir(parents=True, exist_ok=True)
    staged_code = destination / "remote_validation.py"
    staged_metadata = destination / "kernel-metadata.json"
    staged_code.write_text(generated, encoding="utf-8")
    staged_metadata.write_text(
        json.dumps(
            kernel_metadata(kernel, staged_code.name, accelerator, selected_models), indent=2
        )
        + "\n",
        encoding="utf-8",
    )
    return StagedKernel(destination, staged_code, staged_metadata, digest)


def _parse_version(text: str) -> int | None:
    patterns = (
        r"/versions/(\d+)",
        r"\bversion(?:\s+number)?\s*[:#]?\s*(\d+)\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _status_kind(output: str) -> str:
    lowered = output.lower()
    status_match = re.search(r'has status\s+["\']([^"\']+)["\']', lowered)
    if status_match is not None:
        lowered = status_match.group(1)
    if any(word in lowered for word in ("running", "queued", "pending")):
        return "active"
    if any(word in lowered for word in ("complete", "successful", "succeeded")):
        return "complete"
    if any(word in lowered for word in ("error", "failed", "cancelled", "canceled")):
        return "failed"
    return "unknown"


def _is_not_found(result: CommandResult) -> bool:
    message = f"{result.stdout}\n{result.stderr}".lower()
    return result.returncode != 0 and any(
        marker in message
        for marker in (
            "404",
            "not found",
            "does not exist",
            # Kaggle currently returns this 403 response for a valid new slug before
            # its first kernel version exists. Authentication is checked separately
            # immediately before this status probe; the push remains authoritative
            # for ownership and write permission.
            "permission 'kernels.get' was denied",
        )
    )


def _command_error(action: str, result: CommandResult) -> KaggleRunnerError:
    detail = (result.stderr or result.stdout).strip()
    return KaggleRunnerError(f"Kaggle {action} failed: {detail or 'unknown error'}")


def ensure_kaggle_access(cli: KaggleClient) -> None:
    """Verify authentication before creating temporary submission state."""

    result = cli.capture("kernels", "list", "--mine", "--page-size", "1")
    if result.returncode != 0:
        raise _command_error(
            "authentication check",
            result,
        )


def latest_status(cli: KaggleClient, kernel: str) -> CommandResult:
    return cli.capture("kernels", "status", kernel)


def ensure_kernel_idle(cli: KaggleClient, kernel: str) -> None:
    """Reject an overlapping run for a stable kernel slug."""

    result = latest_status(cli, kernel)
    if _is_not_found(result):
        return
    if result.returncode != 0:
        raise _command_error("status check", result)
    if _status_kind(result.stdout) == "active":
        raise KaggleRunnerError(
            f"{kernel} already has a queued or running job. Use "
            f"`jed-validate status --kernel {kernel}` instead."
        )


def _wait_for_terminal_status(
    cli: KaggleClient,
    kernel_ref: str,
    timeout_s: int,
    poll_interval_s: int,
) -> CommandResult:
    deadline = time.monotonic() + timeout_s
    last = CommandResult(1, "", "No status received")
    while time.monotonic() < deadline:
        last = latest_status(cli, kernel_ref)
        if last.returncode == 0:
            kind = _status_kind(last.stdout)
            if kind != "active" and kind != "unknown":
                return last
        time.sleep(poll_interval_s)
    raise KaggleRunnerError(
        f"Timed out after {timeout_s}s while waiting for {kernel_ref}. The Kaggle run may "
        "still be active; use `jed-validate status`."
    )


def _result_directory(root: Path, digest: str) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / f"{timestamp}-{digest[:12]}"


def _find_summary(directory: Path) -> tuple[Path | None, Mapping[str, Any] | None]:
    matches = list(directory.rglob("validation_summary.json"))
    if not matches:
        return None, None
    path = matches[0]
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise KaggleRunnerError(f"Downloaded summary is unreadable: {error}") from error
    if not isinstance(value, dict):
        raise KaggleRunnerError("Downloaded validation summary must be a JSON object")
    return path, value


def fetch_results(
    cli: KaggleClient,
    kernel: str,
    destination: Path,
    version: int | None = None,
) -> tuple[Path | None, Mapping[str, Any] | None]:
    """Download artifacts from one immutable kernel version."""

    kernel_ref = f"{kernel}/{version}" if version is not None else kernel
    destination.mkdir(parents=True, exist_ok=True)
    result = cli.capture(
        "kernels",
        "output",
        kernel_ref,
        "--path",
        str(destination),
        "--force",
        "--file-pattern",
        r"(^|.*/)artifacts/.*",
    )
    if result.returncode != 0:
        raise _command_error("artifact download", result)
    return _find_summary(destination)


def run_remote_validation(
    attack_path: Path,
    *,
    kernel: str,
    accelerator: str = DEFAULT_ACCELERATOR,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    results_root: Path | None = None,
    evaluator_path: Path | None = None,
    cli: KaggleClient | None = None,
    poll_interval_s: int = DEFAULT_POLL_INTERVAL_S,
    models: Sequence[str] = DEFAULT_MODELS,
    budget_s: float = OFFICIAL_BUDGET_S,
    profile: str = "full",
) -> KaggleRunResult:
    """Stage, run, monitor, and download one competition-matched validation."""

    kaggle = cli or KaggleCli()
    evaluator = evaluator_path or default_evaluator_path()
    output_root = results_root or (_repository_root() / "artifacts" / "kaggle")

    validate_attack_source(attack_path)
    ensure_kaggle_access(kaggle)
    ensure_kernel_idle(kaggle, kernel)

    with tempfile.TemporaryDirectory(prefix="jed-kaggle-") as temporary:
        staged = stage_kernel(
            evaluator,
            attack_path,
            kernel,
            accelerator,
            Path(temporary),
            models=models,
            budget_s=budget_s,
            profile=profile,
        )
        print(f"Submitting {attack_path} to https://www.kaggle.com/code/{kernel}")
        pushed = kaggle.capture(
            "kernels",
            "push",
            "--path",
            str(staged.directory),
            "--accelerator",
            accelerator,
            "--timeout",
            str(timeout_s),
        )
        if pushed.stdout:
            print(pushed.stdout.rstrip())
        if pushed.returncode != 0:
            raise _command_error("kernel submission", pushed)
        version = _parse_version(f"{pushed.stdout}\n{pushed.stderr}")
        if version is None:
            raise KaggleRunnerError(
                "Kaggle accepted the kernel but did not report its version number. "
                f"The job may still be active at https://www.kaggle.com/code/{kernel}; "
                "use `jed-validate status` before retrying."
            )

    kernel_ref = f"{kernel}/{version}" if version is not None else kernel
    try:
        # Kaggle's logs and status commands address the current kernel by slug.
        # A version suffix is valid for output downloads, but makes the live-log
        # endpoint request a nonexistent owner/slug/version resource.
        log_code = kaggle.live("kernels", "logs", "--follow", kernel)
        status = latest_status(kaggle, kernel)
        status_kind = _status_kind(status.stdout)
        if log_code != 0 or status.returncode != 0 or status_kind not in {"complete", "failed"}:
            print("Live log stream ended before a terminal status; switching to polling.")
            status = _wait_for_terminal_status(kaggle, kernel, timeout_s, poll_interval_s)
    except KeyboardInterrupt:
        print(
            "\nLocal monitoring stopped; the Kaggle job continues remotely.\n"
            f"Resume with: jed-validate status --follow --kernel {kernel}\n"
            f"Fetch later with: jed-validate fetch --kernel {kernel}",
            file=sys.stderr,
        )
        raise

    run_directory = _result_directory(output_root, staged.attack_sha256)
    summary_path: Path | None = None
    summary: Mapping[str, Any] | None = None
    download_error: KaggleRunnerError | None = None
    try:
        summary_path, summary = fetch_results(kaggle, kernel, run_directory, version)
    except KaggleRunnerError as error:
        download_error = error

    local_manifest = {
        "kernel": kernel,
        "kernel_version": version,
        "kaggle_url": f"https://www.kaggle.com/code/{kernel}",
        "attack_path": str(attack_path.resolve()),
        "attack_sha256": staged.attack_sha256,
        "profile": profile,
        "requested_models": list(models),
        "budget_s_per_model": budget_s,
        "remote_status": status.stdout.strip(),
        "summary_path": str(summary_path) if summary_path else None,
    }
    run_directory.mkdir(parents=True, exist_ok=True)
    (run_directory / "local_run.json").write_text(
        json.dumps(local_manifest, indent=2) + "\n", encoding="utf-8"
    )

    if _status_kind(status.stdout) != "complete":
        raise KaggleRunnerError(
            f"Remote validation failed for {kernel_ref}. Artifacts, when available, are in "
            f"{run_directory}.\n{status.stdout.strip()}"
        )
    if download_error is not None:
        raise download_error
    if summary is None:
        raise KaggleRunnerError(
            f"Kaggle completed but validation_summary.json was not downloaded to {run_directory}"
        )
    if summary.get("attack_sha256") != staged.attack_sha256:
        raise KaggleRunnerError(
            "Downloaded artifacts do not match the submitted attack SHA-256. Another client "
            f"may have updated {kernel}; results were left in {run_directory}."
        )
    return KaggleRunResult(
        kernel=kernel,
        version=version,
        attack_sha256=staged.attack_sha256,
        result_directory=run_directory,
        summary=summary,
    )


def _version_tuple(text: str) -> tuple[int, ...] | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


def _usable_installed_kaggle(executable: str) -> bool:
    try:
        completed = subprocess.run(
            [executable, "--version"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return False
    version = _version_tuple(f"{completed.stdout}\n{completed.stderr}")
    return completed.returncode == 0 and version is not None and version >= MIN_KAGGLE_VERSION


def resolve_kaggle_command(environment: Mapping[str, str] | None = None) -> list[str]:
    """Use a modern installed CLI or isolate one through uvx/Python 3.11."""

    env = os.environ if environment is None else environment
    override = env.get("JED_KAGGLE_BIN")
    if override:
        return shlex.split(override)
    executable = shutil.which("kaggle")
    if executable and _usable_installed_kaggle(executable):
        return [executable]
    uvx = shutil.which("uvx")
    if uvx:
        return [uvx, "--python", "3.11", "--from", "kaggle>=2.2.3", "kaggle"]
    raise KaggleRunnerError(
        "Kaggle CLI >=2.2.3 is required. Install `uv`, then run "
        "`uv tool install --python 3.11 'kaggle>=2.2.3'`, or set JED_KAGGLE_BIN."
    )


def print_summary(summary: Mapping[str, Any], result_directory: Path) -> None:
    """Print the small result surface wanted in an IDE terminal."""

    models = summary.get("models", {})
    print("\nValidation scores")
    print("model      status      score")
    for name in ("gpt_oss", "gemma"):
        value = models.get(name, {}) if isinstance(models, dict) else {}
        status = str(value.get("status", "missing"))
        score = value.get("score_normalized_0_to_1000")
        score_text = "-" if score is None else f"{float(score):.6g}"
        print(f"{name:<10} {status:<11} {score_text}")
    mean = summary.get("mean_score", summary.get("local_public_mean"))
    if mean is not None:
        print(f"mean                   {float(mean):.6g}")
    print(f"Artifacts: {result_directory}")
