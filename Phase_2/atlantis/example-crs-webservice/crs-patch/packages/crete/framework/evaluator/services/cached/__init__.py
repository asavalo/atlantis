from typing import Callable, cast

from crete.atoms.action import Action
from crete.atoms.detection import Detection
from crete.framework.evaluator import EvaluatingContext, EvaluatorProtocol
from crete.framework.evaluator.services.default import DefaultEvaluator


class CachedEvaluator(EvaluatorProtocol):
    def __init__(self) -> None:
        self._default_evaluator = DefaultEvaluator()

    def _evaluate(
        self,
        diff: bytes,
        context: EvaluatingContext,
        detection: Detection,
    ) -> Action:
        return self._default_evaluator.evaluate(context, diff, detection)

    def evaluate(
        self,
        context: EvaluatingContext,
        diff: bytes,
        detection: Detection,
    ) -> Action:
        return cast(
            Callable[..., Action],
            context["memory"].cache(self._evaluate, ignore=["context"]),  # pyright: ignore[reportUnknownMemberType]
        )(diff, context, detection)
