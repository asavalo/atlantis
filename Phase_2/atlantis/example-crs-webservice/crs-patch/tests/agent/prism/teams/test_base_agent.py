from unittest.mock import Mock

import pytest
from crete.framework.agent.services.prism.teams.base_agent import BaseAgent


def test_base_agent_instantiation():
    with pytest.raises(TypeError):
        BaseAgent()  # type: ignore


def test_base_agent_subclass():
    class TestAgent(BaseAgent):
        def __call__(self, *args, **kwargs):  # type: ignore
            return "called"

    agent = TestAgent(llm=Mock())
    assert agent() == "called"

    res = agent._check_content_is_str("test")  # type: ignore
    assert res == "test"
    with pytest.raises(ValueError):
        agent._check_content_is_str([{"text": "test"}])  # type: ignore
