from dataclasses import dataclass
from typing import Any, Callable, TypeAlias, Union

import litellm
from litellm import CustomStreamWrapper
from litellm.types.utils import ModelResponse

from crete.framework.scheduler.tracker.protocols import TrackerProtocol


@dataclass
class _LlmUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0


# Define a type alias for the completion function
CompletionCallable: TypeAlias = Callable[..., Union[ModelResponse, CustomStreamWrapper]]


class LlmCostTracker(TrackerProtocol):
    def __init__(self, max_cost: float) -> None:
        self._max_cost = max_cost
        self._total_cost: float = 0
        self._current_usage: _LlmUsage = _LlmUsage()
        self._original_completion: CompletionCallable

    def is_exhausted(self) -> bool:
        return self._total_cost >= self._max_cost

    def start(self) -> None:
        self._original_completion = litellm.completion  # pyright: ignore[reportUnknownMemberType]
        litellm.completion = self._tracking_completion

    def stop(self) -> None:
        litellm.completion = self._original_completion

    def _tracking_completion(
        self, *args: Any, **kwargs: Any
    ) -> Union[ModelResponse, CustomStreamWrapper]:
        response = self._original_completion(*args, **kwargs)
        self._update_usage(response)
        return response

    def _update_usage(
        self, response: Union[ModelResponse, CustomStreamWrapper]
    ) -> None:
        if not isinstance(response, ModelResponse):
            return

        try:
            self._current_usage = _litellm_usage_from_response(response)
            self._total_cost += _litellm_cost_from_usage(
                model=response["model"], usage=self._current_usage
            )
        except Exception:
            return


def _litellm_cost_from_usage(model: str, usage: _LlmUsage) -> float:
    prompt_cost, completion_cost = litellm.cost_per_token(  # pyright: ignore[reportUnknownMemberType, reportPrivateImportUsage]
        model=model,
        prompt_tokens=usage.prompt_tokens,
        completion_tokens=usage.completion_tokens,
    )
    return prompt_cost + completion_cost


def _litellm_usage_from_response(response: ModelResponse) -> _LlmUsage:
    if "usage" not in response:
        raise ValueError("Response does not contain usage")

    return _LlmUsage(
        prompt_tokens=response["usage"]["prompt_tokens"],
        completion_tokens=response["usage"]["completion_tokens"],
    )
