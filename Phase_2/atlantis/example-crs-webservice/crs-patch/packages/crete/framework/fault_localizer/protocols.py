from typing import Protocol

from crete.atoms.detection import Detection
from crete.framework.fault_localizer.contexts import FaultLocalizationContext
from crete.framework.fault_localizer.models import FaultLocalizationResult


class FaultLocalizerProtocol(Protocol):
    """
    Defines the protocol for a fault localizer that specifies where to patch given a detection.

    Methods:
        localize: Locates the fault in the source code based on the given detection.
    """

    def localize(
        self,
        context: FaultLocalizationContext,
        detection: Detection,
    ) -> FaultLocalizationResult: ...
