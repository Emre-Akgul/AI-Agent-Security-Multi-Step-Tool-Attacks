"""Replay traces into canonical findings without coupling to a model backend."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol, cast

from .cells import cell_signature
from .constants import DEFAULT_SEED, MAX_CANDIDATES
from .predicates import evaluate_predicates
from .validation import SchemaError, validate_candidates, validate_findings, validate_trace


class ReplayBackend(Protocol):
    def replay(self, user_messages: Sequence[str], *, seed: int) -> Mapping[str, Any]: ...


class EnvironmentReplayBackend:
    """Adapter for SDK environments; create a fresh environment per candidate."""

    def __init__(self, environment_factory: Callable[[], Any], *, max_tool_hops: int = 8) -> None:
        self.environment_factory = environment_factory
        self.max_tool_hops = max_tool_hops

    def replay(self, user_messages: Sequence[str], *, seed: int) -> Mapping[str, Any]:
        del seed  # The factory owns seed configuration, matching the SDK evaluator.
        environment = self.environment_factory()
        environment.reset()
        for message in user_messages:
            environment.interact(message, max_tool_hops=self.max_tool_hops)
        return cast(Mapping[str, Any], environment.export_trace_dict())


def finding_from_trace(trace: Mapping[str, Any]) -> dict[str, Any] | None:
    canonical = validate_trace(trace)
    predicates = evaluate_predicates(canonical)
    if not predicates:
        return None
    signature = cell_signature(
        canonical["tool_events"],
        egress_data=canonical["egress"],
        user_messages=canonical["user_messages"],
    )
    return {
        "seed": canonical["seed"],
        "user_messages": canonical["user_messages"],
        "trace": canonical,
        "predicates": predicates,
        "cell_signature": signature,
    }


def replay_candidates(
    candidates: Sequence[Mapping[str, Any]], backend: ReplayBackend, *, seed: int = DEFAULT_SEED
) -> list[dict[str, Any]]:
    canonical = validate_candidates(candidates)
    findings = []
    for candidate in canonical[:MAX_CANDIDATES]:
        finding = finding_from_trace(backend.replay(candidate["user_messages"], seed=seed))
        if finding is not None:
            findings.append(finding)
    return findings


def verify_findings(findings: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Reject findings whose derived predicates or cell hash disagree with their trace."""
    validated = validate_findings(findings)
    verified = []
    for index, finding in enumerate(validated):
        derived = finding_from_trace(finding["trace"])
        if derived is None:
            raise SchemaError(f"findings[{index}]: trace does not trigger a predicate")
        if finding["predicates"] != derived["predicates"]:
            raise SchemaError(f"findings[{index}].predicates: does not match replay trace")
        if finding["cell_signature"]["hash"] != derived["cell_signature"]["hash"]:
            raise SchemaError(f"findings[{index}].cell_signature.hash: does not match replay trace")
        verified.append(derived)
    return verified
