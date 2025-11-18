from crete.atoms.action import Action, SoundDiffAction
from crete.atoms.detection import Detection
from crete.framework.evaluator import EvaluatingContext, EvaluatorProtocol


class DummyEvaluator(EvaluatorProtocol):
    def __init__(self):
        self._index = 0

    def evaluate(
        self,
        context: EvaluatingContext,
        diff: bytes,
        detection: Detection,
    ) -> Action:
        return SoundDiffAction(
            diff=diff,
        )
