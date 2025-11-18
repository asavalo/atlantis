from unittest.mock import Mock

import pytest
from crete.framework.agent.services.prism.states.common_state import PatchStatus
from crete.framework.agent.services.prism.states.evaluation_team_state import (
    EvaluationTeamState,
)
from crete.framework.agent.services.prism.states.inter_team_state import (
    InterTeamState,
    TeamStatus,
)
from crete.framework.agent.services.prism.teams import EvaluationTeam
from langgraph.graph import (
    StateGraph,
)


@pytest.fixture
def evaluation_team() -> EvaluationTeam:
    evaluation_team = EvaluationTeam(llm=Mock())
    evaluation_team.compiled_graph.invoke = Mock(
        return_value={
            "patch_status": PatchStatus.VULNERABLE,
            "evaluation_report": "test report",
            "issue": "test issue",
        }
    )
    return evaluation_team


@pytest.fixture
def state() -> InterTeamState:
    return InterTeamState()


def test_call(evaluation_team: EvaluationTeam, state: InterTeamState) -> None:
    state.team_status = TeamStatus.PATCH
    with pytest.raises(ValueError):
        evaluation_team(state)

    state.team_status = TeamStatus.EVALUATE
    result = evaluation_team(state)
    assert result["patch_status"] == PatchStatus.VULNERABLE
    assert result["evaluation_report"] == "test report"


def test_compile(evaluation_team: EvaluationTeam) -> None:
    assert evaluation_team._compiled_graph is not None  # type: ignore

    evaluation_team._compiled_graph = None  # type: ignore
    with pytest.raises(ValueError):
        evaluation_team.compiled_graph

    # Recompile the graph
    evaluation_team.graph_builder = StateGraph(EvaluationTeamState)
    evaluation_team.compile()
    assert evaluation_team._compiled_graph is not None  # type: ignore
