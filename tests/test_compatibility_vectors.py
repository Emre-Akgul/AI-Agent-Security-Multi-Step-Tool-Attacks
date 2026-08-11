from jed_validator.cells import cell_signature


def test_released_sdk_cell_hash_vectors(post_trace):
    assert cell_signature([], user_messages=["hello"])["hash"] == "0e34a7b5f889cf2a"
    assert (
        cell_signature(
            post_trace["tool_events"],
            egress_data=post_trace["egress"],
            user_messages=post_trace["user_messages"],
        )["hash"]
        == "49d0a761f616fbe3"
    )
