from typing import Protocol

from crete.atoms.detection import Detection
from crete.framework.insighter.contexts import InsighterContext


class InsighterProtocol(Protocol):
    """
    Defines a protocol for an insighter that provides information
    that can help create patches to the LLM.

    Methods:
        create: Creates a prompt containing the insight.
    """

    def create(self, context: InsighterContext, detection: Detection) -> str | None: ...
