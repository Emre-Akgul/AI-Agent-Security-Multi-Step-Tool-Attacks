# JED Validator

Run an `attack.py` from your local IDE against the competition-matched GPT-OSS and
Gemma models on a Kaggle GPU. The Kaggle notebook is the only validation method in
this repository; no local scoring approximation is used.

## Setup

Install the project:

```bash
python3 -m pip install -e '.[dev]'
```

Authenticate with Kaggle once. A current Kaggle CLI can be used directly, or run
through `uvx` so this project's Python 3.10 environment remains unchanged:

```bash
kaggle auth login

# Alternative:
uvx --python 3.11 --from 'kaggle>=2.2.3' kaggle auth login
```

Choose the private kernel that the runner may create and update:

```bash
export JED_KAGGLE_KERNEL=YOUR_USERNAME/aas-remote-validation
```

For non-interactive IDE and Codex runs, these values may instead be stored in the
repository's ignored `.env` file:

```dotenv
KAGGLE_USERNAME=YOUR_USERNAME
KAGGLE_API_TOKEN=YOUR_TOKEN
JED_KAGGLE_KERNEL=YOUR_USERNAME/aas-remote-validation
```

`jed-validate` loads these approved Kaggle variables automatically. Shell variables
take precedence, unrelated `.env` entries are ignored, and the file is never
executed as shell code.

`KAGGLE_USERNAME` is also supported and defaults the kernel slug to
`aas-remote-validation`. An explicit `--kernel` option takes precedence over both
environment variables.

Before the first run, accept the competition rules and confirm that your Kaggle
account can access both referenced GGUF model versions.

## Run validation

```bash
jed-validate kaggle run attack.py
```

The command:

1. checks that `attack.py` defines `AttackAlgorithm.run(...)`;
2. injects only that file into a temporary copy of
   `scripts/aas-local-validation.ipynb`;
3. submits a private `NvidiaTeslaT4` Kaggle notebook;
4. streams its execution logs;
5. evaluates GPT-OSS and Gemma sequentially; and
6. downloads and prints the verified results.

Artifacts are stored under:

```text
artifacts/kaggle/<timestamp>-<attack-sha>/
```

The downloaded manifest's attack SHA-256 must match the submitted file, preventing
a stale or externally replaced run from being reported as the requested validation.

Useful overrides:

```bash
jed-validate kaggle run attack.py \
  --kernel YOUR_USERNAME/another-private-kernel \
  --accelerator NvidiaTeslaT4 \
  --timeout 21600 \
  --results-dir artifacts/kaggle
```

## Resume or fetch a run

Interrupting the local command does not stop the Kaggle job. Resume log streaming or
download the latest artifacts with:

```bash
jed-validate kaggle status --follow
jed-validate kaggle fetch
```

The workflow is deliberately batch-oriented. It does not expose SSH, a VS Code
tunnel, or a persistent GPU session, so idle IDE time does not consume Kaggle GPU
quota.

## Repository layout

```text
attack.py                              Starter attack implementation
scripts/aas-local-validation.ipynb     Authoritative Kaggle evaluator
src/jed_validator/kaggle_runner.py     Submission and monitoring workflow
src/jed_validator/cli.py               jed-validate command
tests/                                 Mocked runner and opt-in Kaggle tests
```

## Development

```bash
pytest
ruff check .
ruff format --check .
mypy src
```

The real Kaggle smoke test is intentionally opt-in because it consumes GPU quota:

```bash
RUN_KAGGLE_INTEGRATION=1 pytest -m kaggle_integration
```
