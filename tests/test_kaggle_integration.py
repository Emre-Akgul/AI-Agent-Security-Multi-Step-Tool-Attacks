from __future__ import annotations

import os
from pathlib import Path

import pytest

from jed_validator.kaggle_runner import resolve_kernel, run_remote_validation


@pytest.mark.kaggle_integration
@pytest.mark.skipif(
    os.environ.get("RUN_KAGGLE_INTEGRATION") != "1",
    reason="set RUN_KAGGLE_INTEGRATION=1 to consume Kaggle GPU quota",
)
def test_real_kaggle_validation_smoke(tmp_path: Path) -> None:
    attack = tmp_path / "attack.py"
    attack.write_text(
        "class AttackAlgorithm:\n    def run(self, env, config):\n        return []\n",
        encoding="utf-8",
    )
    result = run_remote_validation(
        attack,
        kernel=resolve_kernel(),
        results_root=tmp_path / "results",
    )
    assert result.summary is not None
    assert result.summary["status"] == "complete"
    models = result.summary["models"]
    assert isinstance(models, dict)
    assert set(models) == {"gpt_oss", "gemma"}
