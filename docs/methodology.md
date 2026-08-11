# Methodology and evidence

## Authoritative reconstruction

The implementation was reconstructed from these mutually reinforcing sources:

- the released `aicomp-sdk` scoring, predicate, cell, attack contract, guardrail,
  and evaluation modules;
- the competition description and starter notebook;
- a public SDK deep-dive that documents the live successful-call filtering and the
  3.1.x score formula; and
- public, scored Kaggle notebooks that expose candidate counts and observed scores.

The locally obtainable PyPI wheel is 2.0.1, while Kaggle's gated competition input
is reported as 3.1.2. The cell-signature implementation is byte-behavior compatible
with the released 2.0.1 source for stored compatibility vectors. Successful-call
filtering follows the live 3.1.x documentation: denied events affect cell signatures
but cannot trigger predicates.

Sources checked on 2026-08-11:

- [competition page](https://www.kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks)
- [public SDK deep dive](https://www.kaggle.com/code/geokocha/eda-agent-security-sdk-deep-dive)
- [public score calibration notebook](https://www.kaggle.com/code/souldrive/why-your-attack-completes-but-scores-blank)
- [scored 3.1.2 single-post notebook](https://www.kaggle.com/code/pilkwang/ai-agent-v3-1-2-single-post-exfiltration)
- [scored adaptive notebook](https://www.kaggle.com/code/canqiang/aiagsec-ea-b-0721)

## Calibration

`calibration/public_scores.json` contains three public on-leaderboard anchors from
the scored calibration notebook:

| Successful unique findings | Observed | Recomputed |
| ---: | ---: | ---: |
| 256 | 23.04 | 23.04 |
| 420 | 37.80 | 37.80 |
| 560 | 50.40 | 50.40 |

Run `jed-validate calibrate` to reproduce the comparison. These anchors test the
severity, diversity, normalization, and displayed-score scale together. They do not
test stochastic model replay or the private guardrail.

## Trust boundary

Candidate-provided traces, predicates, signatures, and metadata are never accepted
as proof of a score by the real evaluator. The evaluator replays only user-message
chains in a fresh environment. This project preserves that boundary:

- use `validate candidates` before submitting a chain;
- use `EnvironmentReplayBackend` with an actual SDK environment when available;
- use `score traces` only on traces exported from that fresh replay; and
- treat synthetic traces as unit tests, not evidence that an attack will fire.

The private guardrail is undisclosed. No local validator can predict its allow/deny
behavior without replay access, although it can score a trace produced by it.

## Version drift

Competition organizers may update the SDK. Before relying on this validator after an
update, compare constants, `core/predicates.py`, `core/cells.py`, `scoring.py`, and
the replay loop with the new bundle, then add compatibility vectors and public score
anchors rather than silently changing existing calibration evidence.
