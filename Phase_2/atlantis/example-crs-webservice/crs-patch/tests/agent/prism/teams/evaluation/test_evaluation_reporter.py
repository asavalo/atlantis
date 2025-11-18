from unittest.mock import Mock

import pytest
from crete.framework.agent.services.prism.states.evaluation_team_state import (
    EvaluationTeamState,
)
from crete.framework.agent.services.prism.teams.evaluation.evaluation_reporter import (
    EvaluationReporter,
)
from langchain_core.messages import AIMessage


@pytest.fixture
def evaluation_reporter() -> EvaluationReporter:
    mock_evaluation_reporter = EvaluationReporter(llm=Mock())
    mock_evaluation_reporter.llm.invoke = Mock(
        return_value=AIMessage(content="test content")
    )
    return mock_evaluation_reporter


@pytest.fixture
def state() -> EvaluationTeamState:
    return EvaluationTeamState()


def test_basic_call(
    evaluation_reporter: EvaluationReporter, state: EvaluationTeamState
) -> None:
    state.issue = ""
    with pytest.raises(ValueError):
        evaluation_reporter(state)

    state.issue = "test issue"
    state.patch_result = "test issue"
    evaluation_reporter.llm.invoke = Mock(
        return_value=AIMessage(content="test content")
    )
    result = evaluation_reporter(state)
    assert "test content" in result["evaluation_report"]
    assert "test issue" in result["evaluation_report"]
    assert "Additional Issue" not in result["evaluation_report"]

    state.evaluation_report = "test evaluation report"
    state.diff = "test diff"
    evaluation_reporter.llm.invoke = Mock(
        return_value=AIMessage(content="test content")
    )
    result = evaluation_reporter(state)
    assert state.patch_result in result["evaluation_report"]
    assert state.issue in result["evaluation_report"]
    assert "Additional Issue" in result["evaluation_report"]
