"""JED attack trace validation and scoring."""

from .cells import cell_signature
from .predicates import evaluate_predicates
from .replay import verify_findings
from .scoring import score_findings, score_models
from .validation import SchemaError, validate_candidates, validate_findings, validate_trace

__all__ = [
    "SchemaError",
    "cell_signature",
    "evaluate_predicates",
    "score_findings",
    "score_models",
    "validate_candidates",
    "validate_findings",
    "validate_trace",
    "verify_findings",
]

__version__ = "0.1.0"
