from unittest.mock import Mock

import pytest
from crete.framework.agent.services.prism.states.inter_team_state import (
    InterTeamState,
    TeamStatus,
)
from crete.framework.agent.services.prism.states.patch_team_state import (
    PatchTeamState,
)
from crete.framework.agent.services.prism.teams import PatchTeam
from langgraph.graph import (
    StateGraph,
)


@pytest.fixture
def patch_team() -> PatchTeam:
    patch_team = PatchTeam(llm=Mock())
    patch_team.compiled_graph.invoke = Mock(
        return_value={"diff": "test diff", "applied_patches": []}
    )
    return patch_team


@pytest.fixture
def state() -> InterTeamState:
    return InterTeamState()


def test_call(patch_team: PatchTeam, state: InterTeamState) -> None:
    state.team_status = TeamStatus.EVALUATE
    with pytest.raises(ValueError):
        patch_team(state)

    state.team_status = TeamStatus.PATCH
    state.analysis_report = "test analysis report"
    state.evaluation_report = ""
    with pytest.raises(ValueError):
        patch_team(state)

    state.analysis_report = "test analysis report"
    state.evaluation_report = ""
    with pytest.raises(ValueError):
        patch_team(state)

    state.analysis_report = "test analysis report"
    state.evaluation_report = "test evaluation report"
    result = patch_team(state)
    assert result["diff"] == "test diff"


def test_compile(patch_team: PatchTeam) -> None:
    assert patch_team._compiled_graph is not None  # type: ignore

    patch_team._compiled_graph = None  # type: ignore
    with pytest.raises(ValueError):
        patch_team.compiled_graph

    # Recompile the graph
    patch_team.graph_builder = StateGraph(PatchTeamState)
    patch_team.compile()
    assert patch_team._compiled_graph is not None  # type: ignore
