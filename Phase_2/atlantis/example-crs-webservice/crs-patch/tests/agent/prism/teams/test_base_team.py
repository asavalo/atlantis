from unittest.mock import Mock

import pytest
from crete.framework.agent.services.prism.teams.base_team import BaseTeam


def test_base_agent_instantiation():
    with pytest.raises(TypeError):
        BaseTeam()  # type: ignore


def test_base_agent_subclass():
    class TestTeam(BaseTeam):
        def __call__(self, *args, **kwargs):  # type: ignore
            return "called"

        def compile(self) -> None:
            pass

    team = TestTeam(llm=Mock())
    assert team() == "called"
