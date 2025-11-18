import functools
import os
from contextlib import contextmanager
from typing import Any

import litellm
from dotenv import dotenv_values, load_dotenv
from langchain_community.chat_models import ChatLiteLLM
from litellm.main import (
    completion as litellm_completion,  # pyright: ignore[reportUnknownVariableType]
)
from openai import OpenAI
from atlantis.llm_compat import a_chat_completions_create, chat_completions_create


class LlmApiManager:
    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: str,
        max_tokens: int | None = None,
        temperature: float = 1.0,
        custom_llm_provider: str | None = None,
    ) -> None:
        self._model = model
        self._api_key = api_key
        self._base_url = base_url
        self._temperature = temperature
        self._custom_llm_provider = custom_llm_provider

        match max_tokens:
            case None:
                try:
                    model_info = litellm.get_model_info(model)  # pyright: ignore[reportPrivateImportUsage]

                    if model_info["max_tokens"] is None:
                        raise ValueError(
                            f"Model {model} does not have a max_tokens value"
                        )

                    self._max_tokens = model_info["max_tokens"]
                except Exception:
                    self._max_tokens = (
                        8192  # FIXME: Hardcoded default value, should be configurable
                    )
            case _:
                self._max_tokens = max_tokens

    @property
    def model(self) -> str:
        return self._model

    @property
    def max_tokens(self) -> int:
        return self._max_tokens

    @property
    def api_key(self) -> str:
        return self._api_key

    @property
    def base_url(self) -> str:
        return self._base_url

    @staticmethod
    def from_dotenv(model: str, temperature: float = 1.0):
        environment = dotenv_values()

        api_key = environment.get("LITELLM_API_KEY")
        if api_key is None:
            raise ValueError("LITELLM_API_KEY is not set in the environment")

        base_url = environment.get("LITELLM_API_BASE")
        if base_url is None:
            raise ValueError("LITELLM_API_BASE is not set in the environment")

        return LlmApiManager(
            model=model,
            api_key=api_key,
            base_url=base_url,
            temperature=temperature,
        )

    @staticmethod
    def from_environment(
        model: str,
        temperature: float = 1.0,
        custom_llm_provider: str = "openai",
        key_of_api_key: str = "LITELLM_API_KEY",
        key_of_base_url: str = "LITELLM_API_BASE",
        max_tokens: int | None = None,
    ):
        load_dotenv(override=True)

        return LlmApiManager(
            model=model,
            api_key=os.environ[key_of_api_key],
            base_url=os.environ[key_of_base_url],
            temperature=temperature,
            custom_llm_provider=custom_llm_provider,
            max_tokens=max_tokens,
        )

    def langchain_litellm(self):
        model = ChatLiteLLM(
            model=self._model,
            api_key=self._api_key,
            api_base=self._base_url,
            temperature=self._temperature,
            custom_llm_provider=self._custom_llm_provider,
            client=litellm,
        )

        key_attrs = {
            name: getattr(model, name)
            for name in dir(model)
            if name.endswith("_key")
            and name != "api_key"
            and not callable(getattr(model, name))
        }

        # Set all key attributes to None
        for key_name in key_attrs:
            setattr(model, key_name, None)

        return model

    @contextmanager
    def litellm_completion(self):  # pyright: ignore[reportUnknownParameterType]
        @functools.wraps(
            litellm_completion  # pyright: ignore[reportUnknownArgumentType]
        )
        def completion(*args: Any, **kwargs: Any):
            return litellm.completion(  # pyright: ignore[reportUnknownMemberType]
                model=self._model,
                api_key=self._api_key,
                base_url=self._base_url,
                custom_llm_provider=self._custom_llm_provider,
                *args,
                **kwargs,
            )

        yield completion

    @contextmanager
    def litellm_environment(self):
        original_api_key = litellm.api_key
        original_api_base = litellm.api_base

        litellm.api_key = self._api_key
        litellm.api_base = self._base_url

        try:
            yield
        finally:
            litellm.api_key = original_api_key
            litellm.api_base = original_api_base

    @contextmanager
    def openai_chat_completion_create(self):
        with self.openai_client() as client:

            @functools.wraps(client.chat.completions.create)
            def wrapped_create(*args: Any, **kwargs: Any):
                return chat_completions_create(
                    model=self._model,
                    temperature=self._temperature,
                    *args,
                    **kwargs,
                )

            yield wrapped_create

    @contextmanager
    def openai_responses_create(self):
        with self.openai_client() as client:

            @functools.wraps(client.responses.create)
            def wrapped_create(*args: Any, **kwargs: Any):
                return client.responses.create(
                    model=self._model,
                    temperature=self._temperature,
                    *args,
                    **kwargs,
                )

            yield wrapped_create

    @contextmanager
    def openai_client(self):
        client = OpenAI(
            api_key=self._api_key,
            base_url=self._base_url,
        )

        try:
            yield client
        finally:
            client.close()
