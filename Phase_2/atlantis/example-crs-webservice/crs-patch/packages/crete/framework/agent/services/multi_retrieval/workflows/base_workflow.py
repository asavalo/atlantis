from abc import ABC, abstractmethod
from typing import Any

from langchain_core.runnables.config import RunnableConfig


class BaseWorkflow(ABC):
    @abstractmethod
    def compile(self, *args, **kwargs) -> Any:  # type: ignore
        pass  # pragma: no cover

    @abstractmethod
    def invoke(self, state: Any, config: RunnableConfig) -> dict[str, Any] | Any:
        pass  # pragma: no cover
