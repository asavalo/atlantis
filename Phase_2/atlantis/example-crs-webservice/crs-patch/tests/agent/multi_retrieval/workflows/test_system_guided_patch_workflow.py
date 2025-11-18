from unittest.mock import Mock

import pytest
from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.multi_retrieval.states.patch_state import (
    PatchAction,
    PatchState,
)
from crete.framework.agent.services.multi_retrieval.workflows.system_guided_patch_workflow import (
    SystemGuidedPatchWorkflow,
)
from langchain_core.runnables.config import RunnableConfig
from langgraph.graph import END


@pytest.fixture
def system_guided_workflow() -> SystemGuidedPatchWorkflow:
    return SystemGuidedPatchWorkflow()


def test_compile(system_guided_workflow: SystemGuidedPatchWorkflow) -> None:
    system_guided_workflow.compile(llm=Mock())
    assert system_guided_workflow.compiled_graph is not None
    assert system_guided_workflow.docker_evaluator is not None
    assert system_guided_workflow.retrieval_patcher is not None
    assert system_guided_workflow._compiled_graph is not None  # type: ignore


def test_invoke(system_guided_workflow: SystemGuidedPatchWorkflow) -> None:
    system_guided_workflow.compile(llm=Mock())
    state = PatchState(patch_action=PatchAction.ANALYZE_ISSUE)
    config = RunnableConfig()
    system_guided_workflow._compiled_graph.invoke = Mock(  # type: ignore
        return_value={"diff": "test diff"}
    )
    result = system_guided_workflow.invoke(state, config)
    assert isinstance(result, dict)


def test_update(system_guided_workflow: SystemGuidedPatchWorkflow) -> None:
    system_guided_workflow.compile(llm=Mock())
    assert system_guided_workflow.docker_evaluator is not None

    context = Mock(spec=AgentContext)
    detection = Mock(spec=Detection)

    system_guided_workflow.update(context, detection)
    assert system_guided_workflow.docker_evaluator.context == context
    assert system_guided_workflow.docker_evaluator.detection == detection


def test_router_function(system_guided_workflow: SystemGuidedPatchWorkflow) -> None:
    state = PatchState(patch_action=PatchAction.ANALYZE_ISSUE)
    assert system_guided_workflow.router_function(state) == "retrieval_patcher"
    state.patch_action = PatchAction.EVALUATE
    assert system_guided_workflow.router_function(state) == "docker_evaluator"
    state.patch_action = PatchAction.RETRIEVE
    assert system_guided_workflow.router_function(state) == "retrieval_patcher"
    state.patch_action = PatchAction.DONE
    assert system_guided_workflow.router_function(state) == END
