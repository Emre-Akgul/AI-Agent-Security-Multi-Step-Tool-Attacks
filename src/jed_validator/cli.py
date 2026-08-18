"""Command-line interface for authoritative Kaggle GPU validation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .kaggle_runner import (
    DEFAULT_ACCELERATOR,
    DEFAULT_POLL_INTERVAL_S,
    DEFAULT_TIMEOUT_S,
    KaggleCli,
    KaggleRunnerError,
    fetch_results,
    latest_status,
    print_summary,
    resolve_kernel,
    run_remote_validation,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jed-validate")
    sub = parser.add_subparsers(dest="command", required=True)
    kaggle = sub.add_parser("kaggle", help="run authoritative validation on a Kaggle GPU")
    kaggle_sub = kaggle.add_subparsers(dest="kaggle_command", required=True)

    kaggle_run = kaggle_sub.add_parser("run", help="submit, monitor, and download a validation")
    kaggle_run.add_argument("attack", type=Path)
    kaggle_run.add_argument("--kernel")
    kaggle_run.add_argument("--accelerator", default=DEFAULT_ACCELERATOR)
    kaggle_run.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)
    kaggle_run.add_argument("--poll-interval", type=int, default=DEFAULT_POLL_INTERVAL_S)
    kaggle_run.add_argument("--results-dir", type=Path)

    kaggle_status = kaggle_sub.add_parser("status", help="show the latest remote run status")
    kaggle_status.add_argument("--kernel")
    kaggle_status.add_argument("--follow", action="store_true")

    kaggle_fetch = kaggle_sub.add_parser("fetch", help="download latest remote artifacts")
    kaggle_fetch.add_argument("--kernel")
    kaggle_fetch.add_argument("--version", type=int)
    kaggle_fetch.add_argument("--results-dir", type=Path, default=Path("artifacts/kaggle/latest"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        kernel = resolve_kernel(args.kernel)
        kaggle = KaggleCli()
        if args.kaggle_command == "run":
            if args.timeout <= 0 or args.poll_interval <= 0:
                raise KaggleRunnerError("timeout and poll interval must be positive")
            result = run_remote_validation(
                args.attack,
                kernel=kernel,
                accelerator=args.accelerator,
                timeout_s=args.timeout,
                results_root=args.results_dir,
                cli=kaggle,
                poll_interval_s=args.poll_interval,
            )
            assert result.summary is not None
            print_summary(result.summary, result.result_directory)
            print(f"Kaggle: https://www.kaggle.com/code/{result.kernel}")
        elif args.kaggle_command == "status":
            if args.follow:
                return kaggle.live("kernels", "logs", "--follow", kernel)
            status = latest_status(kaggle, kernel)
            if status.returncode != 0:
                detail = (status.stderr or status.stdout).strip()
                raise KaggleRunnerError(f"Kaggle status check failed: {detail}")
            print(status.stdout.rstrip())
        else:
            _, summary = fetch_results(
                kaggle,
                kernel,
                args.results_dir,
                args.version,
            )
            if summary is None:
                raise KaggleRunnerError("validation_summary.json was not present in the output")
            print_summary(summary, args.results_dir)
        return 0
    except (OSError, KaggleRunnerError, ValueError, TypeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
