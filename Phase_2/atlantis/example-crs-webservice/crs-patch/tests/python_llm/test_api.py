import pytest
from python_llm.api.actors import LlmApiManager


@pytest.mark.vcr
@pytest.mark.block_network
@pytest.mark.parametrize(
    "model",
    [
        ("gpt-4o", "openai"),
        # TODO: Fix this
        # ("o3-mini", "openai"),
        ("claude-3-5-sonnet-20241022", "anthropic"),
        ("claude-3-7-sonnet-20250219", "anthropic"),
        ("gemini/gemini-2.0-flash", "openai"),
    ],
)
def test_langchain_chat_model(
    model: tuple[str, str],
):
    llm_api_manager = LlmApiManager.from_environment(
        model=model[0], custom_llm_provider=model[1]
    )

    chat_model = llm_api_manager.langchain_litellm()
    chat_model_response = chat_model.invoke('Say "Hello!"', max_tokens=10)

    assert (
        "Hello!" in chat_model_response.content  # pyright: ignore[reportUnknownMemberType]
    )


@pytest.mark.vcr
@pytest.mark.block_network
def test_langchain_chat_model_anthropic():
    llm_api_manager = LlmApiManager.from_environment(
        model="claude-3-5-sonnet-20241022", custom_llm_provider="anthropic"
    )

    chat_model = llm_api_manager.langchain_litellm()
    chat_model_response = chat_model.invoke('Say "Hello!"', max_tokens=10)

    assert (
        "Hello!" in chat_model_response.content  # pyright: ignore[reportUnknownMemberType]
    )
