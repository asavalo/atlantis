from unittest.mock import Mock

import pytest
from crete.framework.agent.services.prism.states.analysis_team_state import (
    AnalysisTeamState,
)
from crete.framework.agent.services.prism.states.inter_team_state import (
    InterTeamState,
    TeamStatus,
)
from crete.framework.agent.services.prism.teams import AnalysisTeam
from langgraph.graph import (
    StateGraph,
)


@pytest.fixture
def analysis_team() -> AnalysisTeam:
    analysis_team = AnalysisTeam(llm=Mock())
    analysis_team.compiled_graph.invoke = Mock(
        return_value={
            "analysis_report": "test report",
            "relevant_code_snippets": "test relevant code snippets",
        }
    )
    return analysis_team


@pytest.fixture
def state() -> InterTeamState:
    return InterTeamState()


def test_call(analysis_team: AnalysisTeam, state: InterTeamState) -> None:
    state.team_status = TeamStatus.PATCH
    with pytest.raises(ValueError):
        analysis_team(state)

    state.team_status = TeamStatus.ANALYZE
    state.evaluation_report = ""
    with pytest.raises(ValueError):
        analysis_team(state)

    state.evaluation_report = "test evaluation report"
    result = analysis_team(state)
    assert result["analysis_report"] == "test report"
    assert result["relevant_code_snippets"] == "test relevant code snippets"


def test_compile(analysis_team: AnalysisTeam) -> None:
    assert analysis_team._compiled_graph is not None  # type: ignore

    analysis_team._compiled_graph = None  # type: ignore
    with pytest.raises(ValueError):
        analysis_team.compiled_graph

    # Recompile the graph
    analysis_team.graph_builder = StateGraph(AnalysisTeamState)
    analysis_team.compile()
    assert analysis_team._compiled_graph is not None  # type: ignore
