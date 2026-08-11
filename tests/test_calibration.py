import json
from importlib.resources import files
from pathlib import Path

from jed_validator.calibration import check_calibrations


def test_public_calibration_anchors_match():
    result = check_calibrations()
    assert result["passed"] is True
    assert len(result["checks"]) == 3
    assert all(check["absolute_error"] <= 1e-9 for check in result["checks"])


def test_packaged_and_repository_calibrations_match():
    packaged = json.loads(
        files("jed_validator").joinpath("data/public_scores.json").read_text(encoding="utf-8")
    )
    repository = json.loads(Path("calibration/public_scores.json").read_text(encoding="utf-8"))
    assert packaged == repository
