import os
import hashlib
import logging
import pickle
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, TypeVar

from langchain_core.caches import BaseCache
from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage
from langchain_core.messages.ai import AIMessage
from langchain_core.messages.human import HumanMessage
from langchain_core.output_parsers.base import BaseOutputParser
from langchain_core.outputs import Generation
from langchain_core.outputs.chat_generation import ChatGeneration
from langchain_core.outputs.llm_result import LLMResult
from langchain_core.runnables import Runnable
from langchain_core.runnables.base import RunnableSequence
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_fixed,
    wait_random,
)
from vuli.common.singleton import Singleton
from vuli.struct import LLMParseException

T = TypeVar("T")


class DBCache(BaseCache):
    def __init__(self, path: Path):
        self._path = path
        self._create_table()

    def lookup(self, prompt: str, llm_string: str) -> Optional[Sequence[Generation]]:
        result: Optional[Sequence[Generation]] = self._load(
            self._key(prompt, llm_string)
        )
        if (
            not isinstance(result, Sequence)
            or len(result) == 0
            or not isinstance(result[0], ChatGeneration)
        ):
            return None
        for generation in result:
            generation.message.response_metadata["from_cache"] = True
        return result

    def update(self, prompt: str, llm_string: str, return_val: Sequence[Generation]):
        self._save(self._key(prompt, llm_string), return_val)

    def clear():
        pass

    def _create_table(self):
        with sqlite3.connect(str(self._path)) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS objects (
                    key TEXT PRIMARY KEY,
                    data BLOB,
                    last_accessed TIMESTAMP
                )
                """
            )

    def _load(self, key):
        with sqlite3.connect(str(self._path)) as conn:
            row = conn.execute(
                "SELECT data, last_accessed FROM objects WHERE key = ?",
                (key,),
            ).fetchone()

            if row:
                serialized_data, _ = row
                obj = pickle.loads(serialized_data)

                conn.execute(
                    "UPDATE objects SET last_accessed = ? WHERE key = ?",
                    (self._time(), key),
                )
                return obj

        return None

    def _save(self, key, obj):
        serialized_data = pickle.dumps(obj)
        last_accessed = self._time()
        with sqlite3.connect(str(self._path)) as conn:
            conn.execute(
                """
                INSERT INTO objects (key, data, last_accessed)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    data=excluded.data,
                    last_accessed=excluded.last_accessed
                """,
                (key, serialized_data, last_accessed),
            )

    def _key(self, prompt: str, llm_string: str) -> str:
        return hashlib.sha256(f"{prompt}{llm_string}".encode()).hexdigest()

    def _time(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class UsageCallBack(BaseCallbackHandler):
    def __init__(self, cost_function: Callable):
        self._cost: float = 0.0
        self._saved: float = 0.0
        self._cost_function: Callable = cost_function

    def get_usage(self) -> tuple[float, float]:
        return (self._cost, self._saved)

    def reset(self) -> None:
        self._cost: float = 0.0
        self._saved: float = 0.0

    def on_llm_end(self, response: LLMResult, **kwargs) -> Any:
        # At least, gpt-4o, even if there are multiple responses, the token
        # count for all responses is added together and recorded in the
        # metadata of each response. Therefore, only need to use one.
        if len(response.generations) > 0:
            if len(response.generations[0]) > 0:
                message: BaseMessage = response.generations[0][0].message
                prompt_tokens: int = message.usage_metadata["input_tokens"]
                completion_tokens: int = message.usage_metadata["output_tokens"]
                cost: float = self._cost_function(prompt_tokens, completion_tokens)
                self._cost += cost
                if message.response_metadata.get("from_cache", False):
                    self._saved += cost

        # Delete metadata `from_cache` that is created by this tool
        for generations in response.generations:
            for generation in generations:
                if "from_cache" in generation.message.response_metadata:
                    del generation.message.response_metadata["from_cache"]


@dataclass
class ModelMetadata:
    model: BaseChatModel
    usage: UsageCallBack


class ModelManager(metaclass=Singleton):
    def __init__(self):
        self._cache: Optional[BaseCache] = None
        self._lock = threading.Lock()
        self._logger = logging.getLogger("ModelManager")
        self._models: dict = {}
        self._semaphore = threading.Semaphore(1)
        self._max_retries: int = 0

    def add_model(
        self,
        cost_function: Callable,
        model_name: str,
        model: BaseChatModel,
    ) -> None:
        with self._lock:
            self._models[model_name] = ModelMetadata(
                model, UsageCallBack(cost_function)
            )
            self._logger.info(f"Model is added (Name:{model_name})")

    def get_all_model_names(self) -> list[str]:
        return sorted(list(self._models.keys()))

    def get_total_usage(self) -> tuple[float, float]:
        total_cost: float = 0.0
        total_saved: float = 0.0
        for metadata in self._models.values():
            cost, saved = metadata.usage.get_usage()
            total_cost += cost
            total_saved += saved
        return (total_cost, total_saved)

    def print_total_usage(self) -> str:
        result: str = ""
        for name, metadata in self._models.items():
            cost, saved = metadata.usage.get_usage()
            result += f"{name}: (cost: {cost}, saved: {saved})\n"
        if len(result) > 0 and result[-1] == "\n":
            result = result[:-1]
        return result

    def clear(self) -> None:
        with self._lock:
            self._cache = None
            self._models = {}

    def reset_usage(self) -> None:
        with self._lock:
            for metadata in self._models.values():
                metadata.usage.reset()

    def set_cache(self, path: Path) -> None:
        with self._lock:
            self._cache = DBCache(path)
            self._logger.info(f"Cache is set to {path}")

    def set_max_retries(self, max_retries: int) -> None:
        with self._lock:
            self._max_retries: int = max_retries
            self._logger.info(f"Retry limit is set to {max_retries}")

    def set_worker(self, num_workers: int) -> None:
        with self._lock:
            self._semaphore = threading.Semaphore(num_workers)
            self._logger.info(f"semaphore is set to {num_workers}")

    def invoke(
        self,
        messages: list[BaseMessage],
        model_name: str,
        parser: Optional[RunnableSequence],
    ) -> Any:
        with self._semaphore:
            if model_name not in self._models:
                raise RuntimeError(f"Unregistered Model: {model_name}")

            self._logger.debug(f"Model Name: {model_name}")
            [self._logger.debug(x.pretty_repr()) for x in messages]

            metadata: ModelMetadata = self._models[model_name]
            if self._cache:
                metadata.model.cache = self._cache

            for i in range(0, self._max_retries + 1):
                try:
                    message: BaseMessage = self._invoke(
                        metadata.model, messages, {"callbacks": [metadata.usage]}
                    )
                    self._logger.debug(message.pretty_repr())
                    content = "\n".join(
                        c.get("thinking") or c.get("text")
                        for c in message.content
                        if "thinking" in c or "text" in c
                    ) if os.getenv("MODEL_NAME") == "claude" else message.content
                    _, result, _ = self._retry_parse(
                        metadata.model,
                        parser,
                        content,
                        {"callbacks": [metadata.usage]},
                        self._max_retries,
                    )
                    return result
                except LLMParseException as e:
                    if i == self._max_retries:
                        raise e
                except Exception as e:
                    raise e

            raise RuntimeError("Unexpected State")

    def _retry_case(e) -> bool:
        status_code: int = getattr(e, "status_code", 0)
        return status_code == 429 or status_code >= 500

    @retry(
        retry=retry_if_exception(_retry_case),
        wait=wait_fixed(10) + wait_random(0, 2),
        stop=stop_after_attempt(10),
    )
    def _invoke(
        self, runnable: Runnable, messages: list[BaseMessage], config: dict = {}
    ) -> BaseMessage:
        return runnable.invoke(messages, config)

    def _retry_parse(
        self,
        runnable: Runnable,
        parser: BaseOutputParser[T],
        completion: str,
        config: dict = {},
        max_retries=3,
    ):
        retries = 0
        parse_content = completion
        messages: list[BaseMessage] = []
        while retries <= max_retries:
            try:
                return (parse_content, parser.parse(parse_content), False)
            except LLMParseException as e:
                if retries == max_retries:
                    raise e
                else:
                    retries += 1
                    messages.append(AIMessage(content=parse_content))
                    messages.append(HumanMessage(content=str(e)))
                    message: BaseMessage = self._invoke(runnable, messages, config)
                    self._logger.debug(message.pretty_repr())
                    parse_content = message.content
        raise LLMParseException("Failed to parse")
