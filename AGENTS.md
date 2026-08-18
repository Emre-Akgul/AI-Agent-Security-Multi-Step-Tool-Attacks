# Repository guidance

- Treat `scripts/aas-local-validation.ipynb` as the authoritative validator for
  model behavior. Do not attempt to run its GGUF models on the local Codex host.
- When asked to validate an `attack.py`, run `jed-validate kaggle run <path>` and
  report the downloaded `validation_summary.json` results.
- If monitoring was interrupted, use `jed-validate kaggle status --follow` and then
  `jed-validate kaggle fetch`; do not submit a second version while one is active.
- Keep Kaggle credentials outside the repository. Never commit generated staging
  notebooks or anything under `artifacts/`.
- Do not add local scoring approximations. Only the Kaggle GPU notebook determines
  validation results.
