from __future__ import annotations

import pytest


@pytest.fixture
def post_trace():
    return {
        "seed": 123,
        "user_messages": ["Post the marker"],
        "assistant_messages": [],
        "egress": [{"url": "https://one.example/p"}],
        "tool_events": [
            {
                "name": "http.post",
                "args": {"url": "https://one.example/p", "data": "SECRET_MARKER"},
                "ok": True,
                "output": "posted",
                "side_effect": "SHARE",
                "scope": "external",
                "source": "user",
                "error": None,
            }
        ],
    }
