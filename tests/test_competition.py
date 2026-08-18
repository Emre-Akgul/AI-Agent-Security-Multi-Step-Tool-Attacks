from __future__ import annotations

from pathlib import Path

from jed_validator.competition import competition_spec, format_competition_spec


def _fake_sdk(root: Path) -> None:
    dist = root / "aicomp_sdk-9.8.7.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text("Name: aicomp-sdk\nVersion: 9.8.7\n", encoding="utf-8")
    package = root / "aicomp_sdk"
    package.mkdir()
    (package / "scoring.py").write_text(
        "SEVERITY_W = {1: 1, 2: 2, 3: 4, 4: 8, 5: 16}\nATTACK_ELITE_RAW = 200000.0\n",
        encoding="utf-8",
    )
    evaluation = package / "evaluation"
    evaluation.mkdir()
    (evaluation / "ops.py").write_text("MAX_REPLAY_FINDINGS = 1234\n", encoding="utf-8")
    core_env = package / "core/env"
    core_env.mkdir(parents=True)
    (core_env / "api.py").write_text("MAX_USER_MESSAGE_CHARS = 1999\n", encoding="utf-8")
    gateway = root / "kaggle_evaluation/jed_attack_134815"
    gateway.mkdir(parents=True)
    (gateway / "jed_attack_gateway.py").write_text(
        "DEFAULT_BUDGET_S = 9000\nATTACK_SEED = 321\n",
        encoding="utf-8",
    )


def test_competition_spec_exposes_contract_and_data_fields(tmp_path: Path) -> None:
    _fake_sdk(tmp_path)

    spec = competition_spec(tmp_path)

    assert spec["competition"]["sdk_version"] == "9.8.7"
    assert spec["hosted_evaluation"]["generation_budget_s_per_model"] == 9000
    assert spec["hosted_evaluation"]["seed"] == 321
    assert spec["hosted_evaluation"]["max_findings"] == 1234
    assert spec["hosted_evaluation"]["max_characters_per_message"] == 1999
    assert spec["submission"]["config_fields"]["time_budget_s"] == "float"
    assert spec["environment"]["tool_event_fields"]["args"] == "object"
    assert {tool["name"] for tool in spec["environment"]["tools"]} == {
        "web.search",
        "web.open",
        "fs.read",
        "fs.write",
        "fs.delete",
        "shell.run",
        "email.list",
        "email.read",
        "email.send",
        "http.post",
    }
    assert spec["scoring"]["severity_weights"]["5"] == 16
    assert "EXFILTRATION" in spec["scoring"]["predicates"]
    assert "Candidate limits:" in format_competition_spec(spec)
