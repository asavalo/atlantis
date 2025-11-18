import os

from langchain_openai import ChatOpenAI

from sarif.llm.chat.base import DEFAULT_TEMPERATURE, DEFAULT_TIMEOUT, BaseLLM
from sarif.llm.prompt.base import BasePrompt


class OpenAILLM(BaseLLM):
    name = "OpenAI Base"
    vendor = "OpenAI"

    def __init__(
        self,
        prompt: BasePrompt | None,
        model_name: str,
        temperature: float = DEFAULT_TEMPERATURE,
        timeout=DEFAULT_TIMEOUT,
        **kwargs
    ):
        self.api_key = os.getenv("OPENAI_API_KEY")

        if prompt is not None and prompt.logprob_keys:
            model = ChatOpenAI(
                openai_api_key=self.api_key,
                model=model_name,
                temperature=temperature,
                timeout=timeout,
                **kwargs
            ).bind(logprobs=True)
        else:
            model = ChatOpenAI(
                openai_api_key=self.api_key,
                model=model_name,
                temperature=temperature,
                timeout=timeout,
                **kwargs
            )

        super().__init__(model, prompt)


class GPT4ominiLLM(OpenAILLM):
    name = "GPT-4o-mini"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="gpt-4o-mini", **kwargs)


class GPT35LLM(OpenAILLM):
    name = "GPT-3.5"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="gpt-3.5-turbo-0125", **kwargs)


class GPT4LLM(OpenAILLM):
    name = "GPT-4"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="gpt-4-turbo-2024-04-09", **kwargs)


class GPT4oLLM(OpenAILLM):
    name = "GPT-4o"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="gpt-4o", **kwargs)
