from crete.atoms.action import Action
from crete.atoms.detection import Detection
from crete.framework.evaluator import EvaluatingContext, EvaluatorProtocol
from crete.framework.evaluator.services.default import DefaultEvaluator


class MockEvaluator(EvaluatorProtocol):
    def __init__(self):
        self._evaluator = DefaultEvaluator()

    def evaluate(
        self,
        context: EvaluatingContext,
        diff: bytes,
        detection: Detection,
    ) -> Action:
        return self._evaluator.evaluate(context, diff, detection)
