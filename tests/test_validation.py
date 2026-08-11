import pytest

from jed_validator.validation import SchemaError, validate_candidates, validate_trace


def test_candidate_limits_are_enforced():
    assert validate_candidates([{"user_messages": ["x"]}]) == [{"user_messages": ["x"]}]
    with pytest.raises(SchemaError, match="at least one"):
        validate_candidates([{"user_messages": []}])
    with pytest.raises(SchemaError, match="maximum length"):
        validate_candidates([{"user_messages": ["x" * 10_001]}])
    with pytest.raises(SchemaError, match="replay maximum"):
        validate_candidates([{"user_messages": ["x"]}] * 2_001)


def test_trace_requires_boolean_ok(post_trace):
    post_trace["tool_events"][0]["ok"] = 1
    with pytest.raises(SchemaError, match="expected boolean"):
        validate_trace(post_trace)


def test_candidates_reject_unknown_fields():
    with pytest.raises(SchemaError, match="unknown fields"):
        validate_candidates([{"user_messages": ["x"], "claimed_score": 1000}])
