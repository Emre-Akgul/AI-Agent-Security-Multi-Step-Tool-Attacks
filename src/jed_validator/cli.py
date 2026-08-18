"""Command-line workflow for iterative Kaggle GPU experiments."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .competition import DEFAULT_SDK_ROOT, competition_spec, format_competition_spec, sync_sdk
from .experiments import history, latest_report, print_history, print_report
from .kaggle_runner import (
    DEFAULT_ACCELERATOR,
    DEFAULT_POLL_INTERVAL_S,
    DEFAULT_TIMEOUT_S,
    OFFICIAL_BUDGET_S,
    KaggleCli,
    KaggleRunnerError,
    fetch_results,
    latest_status,
    print_summary,
    resolve_kernel,
    run_remote_validation,
)

DEFAULT_RESULTS = Path("artifacts/kaggle")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jed-validate",
        description="Run and compare competition-matched attack experiments on Kaggle GPUs.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="stage, execute, and report one experiment")
    run.add_argument("attack", nargs="?", type=Path, default=Path("attack.py"))
    run.add_argument("--models", choices=("gpt_oss", "gemma", "both"), default="both")
    run.add_argument("--budget", type=float, default=OFFICIAL_BUDGET_S)
    run.add_argument("--profile", help="short experiment label recorded in artifacts")
    run.add_argument("--kernel")
    run.add_argument("--accelerator", default=DEFAULT_ACCELERATOR)
    run.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)
    run.add_argument("--poll-interval", type=int, default=DEFAULT_POLL_INTERVAL_S)
    run.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)

    status = sub.add_parser("status", help="show or follow the active remote run")
    status.add_argument("--kernel")
    status.add_argument("--follow", action="store_true")

    fetch = sub.add_parser("fetch", help="download artifacts from a completed run")
    fetch.add_argument("--kernel")
    fetch.add_argument("--version", type=int)
    fetch.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS / "latest")

    report = sub.add_parser("report", help="show compact feedback from the latest experiment")
    report.add_argument("path", nargs="?", type=Path, default=DEFAULT_RESULTS)
    report.add_argument("--json", action="store_true")

    history_parser = sub.add_parser("history", help="compare recent experiment scores")
    history_parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    history_parser.add_argument("--limit", type=int, default=20)
    history_parser.add_argument("--json", action="store_true")

    sdk = sub.add_parser("sdk", help="download the current official SDK for local inspection")
    sdk.add_argument("action", choices=("sync",))
    sdk.add_argument("--destination", type=Path, default=Path(".jed/competition"))

    competition = sub.add_parser(
        "competition", help="describe official contracts, limits, tools, fields, and scoring"
    )
    competition.add_argument("--sdk-root", type=Path, default=DEFAULT_SDK_ROOT)
    competition.add_argument("--json", action="store_true")
    return parser


def _selected_models(value: str) -> tuple[str, ...]:
    return ("gpt_oss", "gemma") if value == "both" else (value,)


def _run_profile(models: tuple[str, ...], budget_s: float, explicit: str | None) -> str:
    if explicit:
        return explicit
    return "full" if len(models) == 2 and budget_s == OFFICIAL_BUDGET_S else "screen"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "competition":
            spec = competition_spec(args.sdk_root)
            print(json.dumps(spec, indent=2) if args.json else format_competition_spec(spec))
            return 0
        if args.command == "report":
            report = latest_report(args.path)
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                print_report(report)
            return 0
        if args.command == "history":
            if args.limit <= 0:
                raise KaggleRunnerError("history limit must be positive")
            rows = history(args.results_dir, args.limit)
            if args.json:
                print(json.dumps(rows, indent=2))
            else:
                print_history(rows)
            return 0

        kaggle = KaggleCli()
        if args.command == "sdk":
            destination = sync_sdk(kaggle, args.destination)
            print(f"Official competition SDK synced to {destination.resolve()}")
            return 0

        kernel = resolve_kernel(args.kernel)
        if args.command == "run":
            if args.timeout <= 0 or args.poll_interval <= 0 or args.budget <= 0:
                raise KaggleRunnerError("timeout, poll interval, and budget must be positive")
            models = _selected_models(args.models)
            result = run_remote_validation(
                args.attack,
                kernel=kernel,
                accelerator=args.accelerator,
                timeout_s=args.timeout,
                results_root=args.results_dir,
                cli=kaggle,
                poll_interval_s=args.poll_interval,
                models=models,
                budget_s=args.budget,
                profile=_run_profile(models, args.budget, args.profile),
            )
            if result.summary is None:
                raise KaggleRunnerError("validation completed without a summary")
            print_summary(result.summary, result.result_directory)
            print_report(latest_report(result.result_directory))
            print(f"Kaggle: https://www.kaggle.com/code/{result.kernel}")
            return 0
        if args.command == "status":
            if args.follow:
                return kaggle.live("kernels", "logs", "--follow", kernel)
            status_result = latest_status(kaggle, kernel)
            if status_result.returncode != 0:
                detail = (status_result.stderr or status_result.stdout).strip()
                raise KaggleRunnerError(f"Kaggle status check failed: {detail}")
            print(status_result.stdout.rstrip())
            return 0

        _, summary = fetch_results(kaggle, kernel, args.results_dir, args.version)
        if summary is None:
            raise KaggleRunnerError("validation_summary.json was not present in the output")
        print_summary(summary, args.results_dir)
        print_report(latest_report(args.results_dir))
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, KaggleRunnerError, ValueError, TypeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
