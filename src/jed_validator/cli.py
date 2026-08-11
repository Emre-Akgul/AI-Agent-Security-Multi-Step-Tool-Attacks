"""Command-line interface for schema checks, trace scoring, and calibration."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .calibration import check_calibrations
from .replay import finding_from_trace, verify_findings
from .scoring import score_findings, score_models
from .validation import SchemaError, validate_candidates, validate_findings, validate_trace


def _load(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _emit(value: Any) -> None:
    json.dump(value, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jed-validate")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate candidates, traces, or findings")
    validate.add_argument("kind", choices=("candidates", "trace", "findings"))
    validate.add_argument("path", type=Path)
    score = sub.add_parser("score", help="score replay traces or canonical findings")
    score.add_argument("kind", choices=("traces", "findings", "rows"))
    score.add_argument("path", type=Path)
    calibrate = sub.add_parser("calibrate", help="check known public score anchors")
    calibrate.add_argument("path", nargs="?", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            value = _load(args.path)
            if args.kind == "candidates":
                count = len(validate_candidates(value))
            elif args.kind == "trace":
                validate_trace(value)
                count = 1
            else:
                count = len(validate_findings(value))
            _emit({"valid": True, "count": count})
        elif args.command == "score":
            value = _load(args.path)
            if args.kind == "traces":
                findings = [
                    item for trace in value if (item := finding_from_trace(trace)) is not None
                ]
                _emit(score_findings(findings))
            elif args.kind == "findings":
                _emit(score_findings(verify_findings(value)))
            else:
                _emit(score_models({name: verify_findings(rows) for name, rows in value.items()}))
        else:
            _emit(check_calibrations(args.path))
        return 0
    except (OSError, json.JSONDecodeError, SchemaError, ValueError, TypeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
