from typing import Protocol

from crete.framework.patch_scorer.contexts import PatchScoringContext


class PatchScorerProtocol(Protocol):
    def score(self, context: PatchScoringContext, diff: str) -> float: ...
