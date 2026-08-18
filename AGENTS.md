# Codex operating instructions

The repository has one product objective: maximize the replay-validated score of
`attack.py` in Kaggle's AI Agent Security competition sandbox.

- Read `CODEX_GOAL.md` and `COMPETITION.md` before changing the candidate.
- Treat `attack.py` as the only submission source. Infrastructure changes are in
  scope only when they improve measurement reliability or iteration speed.
- Run `jed-validate sdk sync` before relying on SDK behavior; inspect `.jed/competition`
  rather than guessing about predicates, cells, fixtures, or replay limits.
- Use a single GPT-OSS screen first, then Gemma, then a full two-model confirmation.
  Compare experiments with `jed-validate history` and `jed-validate report --json`.
- Make one measurable strategy change per screen and preserve the best-known candidate.
  A run is an improvement only when its SHA-matched artifacts improve replayed score or
  reliability; prompt count alone is not evidence.
- Never launch a second Kaggle version while one is active. Never submit to the public
  leaderboard unless the user explicitly asks.
- This work is limited to the synthetic competition environment. Do not introduce real
  credentials, real recipients, or real network targets.
- Never commit `.env`, `.jed/`, `artifacts/`, generated Kaggle scripts, or credentials.
