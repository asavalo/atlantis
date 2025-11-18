from unittest.mock import Mock

import pytest
from crete.framework.agent.services.multi_retrieval.nodes.llm_node import LLMNode


def test_check_content_is_str() -> None:
    class TestNode(LLMNode):
        def __call__(self, *args, **kwargs):  # type: ignore
            return "called"

    llm_node = TestNode(llm=Mock())

    with pytest.raises(ValueError):
        llm_node._check_content_is_str(None)  # type: ignore

    with pytest.raises(ValueError):
        llm_node._check_content_is_str(123)  # type: ignore

    content = llm_node._check_content_is_str("string content")  # type: ignore
    assert content == "string content"
