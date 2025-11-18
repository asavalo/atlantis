from typing import Any

import pytest
from langchain.tools import tool  # type: ignore
from langchain_core.messages import HumanMessage
from litellm.exceptions import InternalServerError, RateLimitError
from litellm.llms.anthropic.common_utils import AnthropicError
from pytest_mock import MockerFixture
from python_llm.agents.react import run_react_agent
from python_llm.api.actors import LlmApiManager


@tool
def add(a: int, b: int) -> str:
    """Add two numbers"""
    return str(a + b)


def test_run_react_agent_fail_by_internal_server_error(mocker: MockerFixture):
    mock_completion = mocker.patch("litellm.completion")

    def side_effect_function(*args: Any, **kwargs: Any):
        raise InternalServerError(
            message="Internal Server Error",
            llm_provider="openai",
            model="gpt-4o",
        )

    mock_completion.side_effect = side_effect_function

    run_react_agent(
        main_llm_api_manager=LlmApiManager.from_environment(
            model="gpt-4o", custom_llm_provider="openai"
        ),
        tools=[],
        messages=[HumanMessage(content="Hello, world!")],
    )


def test_run_react_agent_fail_by_rate_limit_error(mocker: MockerFixture):
    mock_completion = mocker.patch("litellm.completion")

    def side_effect_function(*args: Any, **kwargs: Any):
        raise RateLimitError(
            message="Rate limit exceeded",
            llm_provider="openai",
            model="gpt-4o",
        )

    mock_completion.side_effect = side_effect_function

    run_react_agent(
        main_llm_api_manager=LlmApiManager.from_environment(
            model="gpt-4o", custom_llm_provider="openai"
        ),
        tools=[],
        messages=[HumanMessage(content="Hello, world!")],
    )


@pytest.mark.vcr()
def test_run_react_agent_fail_by_timeout_by_anthropic_error(mocker: MockerFixture):
    mock_completion = mocker.patch(
        "litellm.llms.anthropic.chat.handler.AnthropicChatCompletion.completion"
    )

    def side_effect_function(*args: Any, **kwargs: Any):
        raise AnthropicError(
            status_code=408,
            message="litellm.Timeout: Connection timed out.",
            headers=None,
        )

    mock_completion.side_effect = side_effect_function

    run_react_agent(
        main_llm_api_manager=LlmApiManager.from_environment(
            model="claude-sonnet-4-20250514", custom_llm_provider="anthropic"
        ),
        tools=[add],
        messages=[HumanMessage(content="What's one plus one?")],
    )
