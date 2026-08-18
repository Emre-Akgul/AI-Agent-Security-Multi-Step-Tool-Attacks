# JED attack lab

An experiment workspace for improving one competition submission: [`attack.py`](attack.py).
Codex edits that file locally; Kaggle supplies competition-matched GPT-OSS and Gemma GPUs;
the CLI preserves SHA-verified results and makes runs comparable.

## Setup

```bash
python3 -m pip install -e '.[dev]'
kaggle auth login  # or: uvx --python 3.11 --from 'kaggle>=2.2.3' kaggle auth login
```

Put the non-interactive settings in the ignored `.env` file:

```dotenv
KAGGLE_USERNAME=YOUR_USERNAME
KAGGLE_API_TOKEN=YOUR_TOKEN
JED_KAGGLE_KERNEL=YOUR_USERNAME/aas-remote-validation
```

Download the current official SDK for Codex to inspect locally:

```bash
jed-validate sdk sync
```

It is stored under ignored `.jed/competition/`; no SDK snapshot or synthetic fixture
credential is committed.

Surface the competition description and exact data fields after syncing:

```bash
jed-validate competition
jed-validate competition --json
```

The JSON form exposes the submission/config schema, candidate limits, trace and tool-event
fields, every tool's arguments, fixtures, predicates, severity weights, score formula, and
canonical cell dimensions. Values are read from the refreshed SDK where they determine
scoring or hosted limits; [`COMPETITION.md`](COMPETITION.md) is the shorter human guide.

## Optimization workflow

Use a short single-model screen while developing a hypothesis:

```bash
jed-validate run attack.py \
  --models gpt_oss \
  --budget 600 \
  --profile unique-http-cells
```

Confirm an improvement on Gemma, then increase the budget. A full competition-parameter
run uses both models and the official 8,750-second per-model budget:

```bash
jed-validate run attack.py --models gemma --budget 600 --profile unique-http-cells-gemma
jed-validate run attack.py
```

The full run can take many hours for an adaptive candidate. `--timeout` defaults to 12
hours. Interrupting local monitoring does not stop the Kaggle job:

```bash
jed-validate status --follow
jed-validate fetch
```

Inspect the latest result or compare experiments:

```bash
jed-validate report
jed-validate report --json
jed-validate history
```

Each run records its profile, requested models, budget, attack SHA-256, scores, predicate
counts, severity counts, successful tools, score-cell hashes, and successful prompt chains
under `artifacts/kaggle/<timestamp>-<sha>/`. Downloaded results are rejected if the attack
SHA does not match the submitted source.

## Using a Codex goal

Point Codex at [`CODEX_GOAL.md`](CODEX_GOAL.md), or use this objective:

> Maximize the mean replay-validated score of `attack.py` across GPT-OSS and Gemma. Follow
> CODEX_GOAL.md, use the official SDK as source of truth, run bounded Kaggle screens, keep
> the best-known candidate, and continue with evidence-driven hypotheses while quota and
> the goal budget permit.

[`AGENTS.md`](AGENTS.md) keeps autonomous work scoped to the synthetic competition and
prevents accidental leaderboard submissions, overlapping jobs, or credential commits.

## Architecture

The repository intentionally contains no Jupyter notebook. `scripts/remote_validation.py`
is ordinary testable Python. At run time the CLI embeds `attack.py` plus the selected model
and budget into a temporary Kaggle script, attaches only the requested model data, runs it
privately, and downloads the structured artifacts. Temporary scripts and credentials are
never uploaded together.

Development checks:

```bash
ruff check .
ruff format --check .
pytest
mypy src
```

The opt-in integration test consumes Kaggle GPU quota:

```bash
RUN_KAGGLE_INTEGRATION=1 pytest -m kaggle_integration
```
