"""Calibration checks against publicly documented leaderboard anchors."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

from .constants import ATTACK_ELITE_RAW, SEVERITY_WEIGHTS


def expected_single_exfil_score(findings: int, unique_cells: int | None = None) -> float:
    cells = findings if unique_cells is None else unique_cells
    raw = findings * SEVERITY_WEIGHTS[5] + cells * 2
    return min(1000.0, raw / ATTACK_ELITE_RAW * 1000.0)


def check_calibrations(path: Path | None = None) -> dict[str, Any]:
    if path is None:
        source = files("jed_validator").joinpath("data/public_scores.json")
        records = json.loads(source.read_text(encoding="utf-8"))
    else:
        source = path
        records = json.loads(path.read_text(encoding="utf-8"))
    checks = []
    for record in records:
        if "row_findings" in record:
            row_scores = [
                expected_single_exfil_score(int(count)) for count in record["row_findings"]
            ]
            calculated = sum(row_scores) / len(row_scores)
        else:
            calculated = expected_single_exfil_score(
                int(record["findings"]), int(record.get("unique_cells", record["findings"]))
            )
        observed = float(record["observed_score"])
        tolerance = float(record.get("tolerance", 1e-9))
        checks.append(
            {
                "id": record["id"],
                "calculated_score": calculated,
                "observed_score": observed,
                "absolute_error": abs(calculated - observed),
                "passed": abs(calculated - observed) <= tolerance,
            }
        )
    return {
        "source": str(source),
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
    }
