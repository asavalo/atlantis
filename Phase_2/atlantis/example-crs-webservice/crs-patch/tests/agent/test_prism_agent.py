from pathlib import Path
from unittest.mock import Mock

import pytest
from crete.atoms.action import NoPatchAction, SoundDiffAction
from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.prism import PrismAgent
from python_llm.api.actors import LlmApiManager


@pytest.fixture
def prism_agent() -> PrismAgent:
    return PrismAgent(
        llm_api_manager=LlmApiManager(
            model="gpt-4o",
            api_key="test_api_key",
            base_url="test_base_url",
        ),
        recursion_limit=75,
    )


@pytest.fixture
def context() -> AgentContext:
    return {
        "pool": Mock(),
        "logger": Mock(),
        "evaluator": Mock(),
        "output_directory": Path("/test/output"),
        "logging_prefix": "test_prefix",
        "crash_log_analyzer": Mock(),
        "call_trace_snapshot": Mock(),
        "language_parser": Mock(),
        "lsp_client": Mock(),
        "previous_action": Mock(),
        "memory": Mock(),
        "sanitizer_name": "address",
    }


@pytest.fixture
def detection() -> Detection:
    return Mock(spec=Detection)


def test_act_no_patch(
    prism_agent: PrismAgent, context: AgentContext, detection: Detection
) -> None:
    prism_agent.compiled_graph.invoke = Mock(return_value={"diff": ""})
    actions = list(prism_agent.act(context, detection))
    assert len(actions) == 1
    assert isinstance(actions[0], NoPatchAction)


def test_act_with_patch(
    prism_agent: PrismAgent, context: AgentContext, detection: Detection
) -> None:
    prism_agent.compiled_graph.invoke = Mock(return_value={"diff": "some diff"})
    context["evaluator"].evaluate = Mock(
        return_value=SoundDiffAction(diff=b"some diff")
    )
    actions = list(prism_agent.act(context, detection))
    assert len(actions) == 1
    assert isinstance(actions[0], SoundDiffAction)


def test_act_with_exception(
    prism_agent: PrismAgent, context: AgentContext, detection: Detection
) -> None:
    prism_agent._backup_llm_api_manager = None  # type: ignore
    prism_agent.compiled_graph.invoke = Mock(side_effect=Exception)
    context["evaluator"].evaluate = Mock(
        return_value=SoundDiffAction(diff=b"some diff")
    )
    actions = list(prism_agent.act(context, detection))
    assert len(actions) == 1
    assert isinstance(actions[0], NoPatchAction)


def test_act_with_backup_patch(
    prism_agent: PrismAgent, context: AgentContext, detection: Detection
) -> None:
    from litellm.exceptions import RateLimitError

    assert prism_agent.analysis_team is not None
    assert prism_agent.evaluation_team is not None
    assert prism_agent.patch_team is not None
    prism_agent.analysis_team.set_llm = Mock()
    prism_agent.evaluation_team.set_llm = Mock()
    prism_agent.patch_team.set_llm = Mock()

    prism_agent._backup_llm_api_manager = LlmApiManager(  # type: ignore
        model="gpt-4o",
        api_key="test_api_key",
        base_url="test_base_url",
    )
    prism_agent.compiled_graph.invoke = Mock(
        side_effect=[RateLimitError, {"diff": "some diff"}]
    )
    context["evaluator"].evaluate = Mock(
        return_value=SoundDiffAction(diff=b"some diff")
    )
    actions = list(prism_agent.act(context, detection))
    assert len(actions) == 1
    assert isinstance(actions[0], SoundDiffAction)
    assert prism_agent.analysis_team.set_llm.call_count == 1
    assert prism_agent.evaluation_team.set_llm.call_count == 1
    assert prism_agent.patch_team.set_llm.call_count == 1
    assert prism_agent.compiled_graph.invoke.call_count == 2


def test_act_with_backup_exception(
    prism_agent: PrismAgent, context: AgentContext, detection: Detection
) -> None:
    from litellm.exceptions import RateLimitError

    assert prism_agent.analysis_team is not None
    assert prism_agent.evaluation_team is not None
    assert prism_agent.patch_team is not None
    prism_agent.analysis_team.set_llm = Mock()
    prism_agent.evaluation_team.set_llm = Mock()
    prism_agent.patch_team.set_llm = Mock()

    prism_agent._backup_llm_api_manager = LlmApiManager(  # type: ignore
        model="gpt-4o",
        api_key="test_api_key",
        base_url="test_base_url",
    )

    prism_agent.compiled_graph.invoke = Mock(side_effect=RateLimitError)
    context["evaluator"].evaluate = Mock(
        return_value=SoundDiffAction(diff=b"some diff")
    )
    context["evaluator"].evaluate = Mock(
        return_value=SoundDiffAction(diff=b"some diff")
    )
    actions = list(prism_agent.act(context, detection))
    assert len(actions) == 1
    assert isinstance(actions[0], NoPatchAction)
    assert prism_agent.analysis_team.set_llm.call_count == 1
    assert prism_agent.evaluation_team.set_llm.call_count == 1
    assert prism_agent.patch_team.set_llm.call_count == 1
    assert prism_agent.compiled_graph.invoke.call_count == 2
