import tempfile
import threading
from pathlib import Path
from queue import Queue

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage
from langchain_core.messages.ai import AIMessage
from langchain_core.output_parsers.base import BaseOutputParser
from langchain_core.output_parsers.string import StrOutputParser
from langchain_core.outputs import ChatResult
from langchain_core.outputs.chat_generation import ChatGeneration, Generation
from vuli.model_manager import DBCache, ModelManager
from vuli.struct import LLMParseException


class MockChatModel(BaseChatModel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._counter: int = 0

    def _generate(self, messages: list[BaseMessage], *args, **kwargs) -> ChatResult:
        # NOTE: This is actual response from gpt-4o
        return ChatResult(
            generations=[
                ChatGeneration(
                    text=f"{str(self._counter)}",
                    message=AIMessage(
                        content="Euphoria.",
                        additional_kwargs={"refusal": None},
                        response_metadata={
                            "token_usage": {
                                "completion_tokens": 4,
                                "prompt_tokens": 13,
                                "total_tokens": 17,
                                "completion_tokens_details": {
                                    "accepted_prediction_tokens": 0,
                                    "audio_tokens": 0,
                                    "reasoning_tokens": 0,
                                    "rejected_prediction_tokens": 0,
                                },
                                "prompt_tokens_details": {
                                    "audio_tokens": 0,
                                    "cached_tokens": 0,
                                },
                            },
                            "model_name": "gpt-4o-2024-08-06",
                            "system_fingerprint": "fp_b7d65f1a5b",
                            "finish_reason": "stop",
                            "logprobs": None,
                        },
                        id="run-43603557-546f-4d78-9b3a-dd7f8755f8c7-0",
                        usage_metadata={
                            "input_tokens": 13,
                            "output_tokens": 4,
                            "total_tokens": 17,
                            "input_token_details": {
                                "audio": 0,
                                "cache_read": 0,
                            },
                            "output_token_details": {
                                "audio": 0,
                                "reasoning": 0,
                            },
                        },
                    ),
                )
            ]
        )

    @property
    def _llm_type(self) -> str:
        "mock"


class MockParser(BaseOutputParser[str]):
    def __init__(self, success_cond: int):
        super().__init__()
        self._success_cond: int = success_cond
        self._counter: int = 0

    def reset(self) -> None:
        self._counter: int = 0

    def parse(self, text: str) -> str:
        if self._counter >= self._success_cond:
            return str(self._counter)
        else:
            self._counter += 1
            raise LLMParseException()


def test_cache():
    """
    Test
        ModelManager should preserver info to calculate usage
    """
    t = tempfile.NamedTemporaryFile()
    manager = ModelManager()
    manager.add_model(lambda input, output: input + output, "mock", MockChatModel())
    manager.reset_usage()
    manager.set_cache(Path(t.name))
    manager.invoke([], "mock", StrOutputParser())
    manager.set_cache(Path(t.name))
    manager.invoke([], "mock", StrOutputParser())
    cost, saved = manager.get_total_usage()
    assert cost == 34.0 and saved == 17.0


def test_cost():
    """
    Test
        Manager can return the cost of interaction
    """
    manager = ModelManager()
    manager.clear()
    manager.add_model(lambda input, output: input + output, "mock", MockChatModel())
    manager.invoke([], "mock", StrOutputParser())
    assert manager.get_total_usage() == (17.0, 0.0)


def test_used():
    manager = ModelManager()
    manager.clear()
    manager.add_model(lambda input, output: input + output, "mock", MockChatModel())
    manager.set_max_retries(0)

    # When First Call Failed
    with pytest.raises(LLMParseException):
        manager.invoke([], "mock", MockParser(10))
    assert manager.get_total_usage() == (17.0, 0.0)

    # When Retry Failed
    manager.set_max_retries(3)
    manager.reset_usage()
    with pytest.raises(LLMParseException):
        manager.invoke([], "mock", MockParser(20))
    assert manager.get_total_usage() == (272.0, 0.0)

    # When Retry Succeed
    manager.reset_usage()
    manager.invoke([], "mock", MockParser(2))
    assert manager.get_total_usage() == (51.0, 0.0)


def test_get_all_model_names():
    manager = ModelManager()
    manager.clear()
    manager.add_model(lambda input, output: input + output, "mock1", MockChatModel())
    assert manager.get_all_model_names() == ["mock1"]

    manager.add_model(
        lambda input, output: input + output * 2, "mock2", MockChatModel()
    )
    assert manager.get_all_model_names() == ["mock1", "mock2"]


def test_cache_in_parallel():
    def work(queue: Queue, cache: DBCache, prompt: str, llm_string: str) -> None:
        result = cache.lookup(prompt, llm_string)
        queue.put(result)

    t = tempfile.NamedTemporaryFile()
    cache: DBCache = DBCache(Path(t.name))
    answer: list[Generation] = [
        ChatGeneration(
            text="hello",
            message=AIMessage(content="hello", response_metadata={"from_cache": True}),
        )
    ]
    cache.update("prompt", "llm_string", answer)
    queue: Queue = Queue()
    thread = threading.Thread(target=work, args=(queue, cache, "prompt", "llm_string"))
    thread.start()
    thread.join()
    assert queue.qsize() == 1
    assert queue.get() == answer
