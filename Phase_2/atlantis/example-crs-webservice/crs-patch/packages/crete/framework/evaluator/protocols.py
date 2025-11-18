from typing import Protocol

from crete.atoms.action import Action
from crete.atoms.detection import Detection
from crete.framework.evaluator.contexts import EvaluatingContext


class EvaluatorProtocol(Protocol):
    """
    Defines the protocol for an evaluator that assesses the effectiveness of a code diff.

    The evaluator is responsible for analyzing a given code diff in the context of a specific
    detection and environment. It determines whether the diff successfully addresses the
    detected issue, introduces new problems, or fails to resolve the original problem.

    Methods:
        evaluate: Evaluates a code diff and returns an Action object representing the outcome.

    The evaluate method takes into account the current context, the proposed code diff,
    the original detection, and the environment in which the code operates. It then returns
    an Action object that encapsulates the result of the evaluation, which could indicate
    a successful fix, a compilation error, a remaining vulnerability, or other possible outcomes.
    """

    def evaluate(
        self,
        context: EvaluatingContext,
        diff: bytes,
        detection: Detection,
    ) -> Action: ...
