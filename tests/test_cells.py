from jed_validator.cells import cell_signature


def test_domain_affects_cell(post_trace):
    event = post_trace["tool_events"][0]
    first = cell_signature(
        [event], egress_data=post_trace["egress"], user_messages=post_trace["user_messages"]
    )
    event2 = {**event, "args": {**event["args"], "url": "https://two.example/p"}}
    second = cell_signature(
        [event2], egress_data=post_trace["egress"], user_messages=post_trace["user_messages"]
    )
    assert first["hash"] != second["hash"]
    assert first["sensitive_tools"] == ["http.post:one.example"]
    assert len(first["hash"]) == 16
