from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import pytest
from crete.atoms.action import NoPatchAction, SoundDiffAction
from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.multi_retrieval import MultiRetrievalPatchAgent
from python_llm.api.actors import LlmApiManager


@pytest.fixture
def agent() -> MultiRetrievalPatchAgent:
    return MultiRetrievalPatchAgent(
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
    agent: MultiRetrievalPatchAgent, context: AgentContext, detection: Detection
) -> None:
    agent.workflow.invoke = Mock(return_value={"diff": ""})
    actions = list(agent.act(context, detection))
    assert len(actions) == 1
    assert isinstance(actions[0], NoPatchAction)


def test_act_with_patch(
    agent: MultiRetrievalPatchAgent, context: AgentContext, detection: Detection
) -> None:
    agent.workflow.invoke = Mock(return_value={"diff": "some diff"})
    context["evaluator"].evaluate = Mock(
        return_value=SoundDiffAction(diff=b"some diff")
    )
    agent._log_state_to_file = Mock()  # type: ignore
    actions = list(agent.act(context, detection))
    assert len(actions) == 1
    assert isinstance(actions[0], SoundDiffAction)


def test_act_with_exception(
    agent: MultiRetrievalPatchAgent, context: AgentContext, detection: Detection
) -> None:
    agent._backup_llm_api_manager = None  # type: ignore
    agent.workflow.invoke = Mock(side_effect=Exception)
    context["evaluator"].evaluate = Mock(
        return_value=SoundDiffAction(diff=b"some diff")
    )
    agent._log_state_to_file = Mock()  # type: ignore
    actions = list(agent.act(context, detection))
    assert len(actions) == 1
    assert isinstance(actions[0], NoPatchAction)


def test_act_with_backup_patch(
    agent: MultiRetrievalPatchAgent, context: AgentContext, detection: Detection
) -> None:
    from litellm.exceptions import RateLimitError

    agent._backup_llm_api_manager = LlmApiManager(  # type: ignore
        model="gpt-4o",
        api_key="test_api_key",
        base_url="test_base_url",
    )
    agent.workflow.set_llm = Mock()

    agent.workflow.invoke = Mock(side_effect=[RateLimitError, {"diff": "some diff"}])
    context["evaluator"].evaluate = Mock(
        return_value=SoundDiffAction(diff=b"some diff")
    )
    agent._log_state_to_file = Mock()  # type: ignore
    actions = list(agent.act(context, detection))
    assert len(actions) == 1
    assert isinstance(actions[0], SoundDiffAction)
    assert agent.workflow.set_llm.call_count == 1
    assert agent.workflow.invoke.call_count == 2


def test_act_with_backup_exception(
    agent: MultiRetrievalPatchAgent, context: AgentContext, detection: Detection
) -> None:
    from litellm.exceptions import RateLimitError

    agent._backup_llm_api_manager = LlmApiManager(  # type: ignore
        model="gpt-4o",
        api_key="test_api_key",
        base_url="test_base_url",
    )
    agent.workflow.set_llm = Mock()

    agent.workflow.invoke = Mock(side_effect=Exception)
    context["evaluator"].evaluate = Mock(
        return_value=SoundDiffAction(diff=b"some diff")
    )
    agent._log_state_to_file = Mock()  # type: ignore
    agent.workflow.invoke = Mock(side_effect=RateLimitError)
    actions = list(agent.act(context, detection))
    assert len(actions) == 1
    assert isinstance(actions[0], NoPatchAction)
    assert agent.workflow.set_llm.call_count == 1
    assert agent.workflow.invoke.call_count == 2


def test_log_state_to_file(agent: MultiRetrievalPatchAgent) -> None:
    import json

    state = {
        "messages": [
            {"role": "user", "content": "message1"},
            {"role": "assistant", "content": "message2"},
        ],
        "diff": "some diff",
        "n_evals": 1,
        "tests_log": "tests log",
    }
    file_content = json.dumps(
        {
            "model": agent._llm_api_manager.model,  # type: ignore
            "messages": state["messages"],
            "diff": state["diff"],
            "n_evals": state["n_evals"],
            "tests_log": state["tests_log"],
        },
        ensure_ascii=False,
        indent=4,
    )
    output_directory = Path("test/output")
    with patch("builtins.open", mock_open()) as mock_file:
        agent._log_state_to_file(output_directory, state, agent._llm_api_manager.model)  # type: ignore
        mock_file.assert_called_once_with(
            output_directory / "messages.json", "w", encoding="utf-8"
        )
        mock_file().write.assert_called_once_with(file_content)
