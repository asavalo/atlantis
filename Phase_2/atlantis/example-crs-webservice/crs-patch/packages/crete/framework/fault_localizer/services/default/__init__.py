from crete.atoms.detection import Detection
from crete.framework.fault_localizer.contexts import FaultLocalizationContext
from crete.framework.fault_localizer.models import FaultLocalizationResult
from crete.framework.fault_localizer.protocols import FaultLocalizerProtocol


class DefaultFaultLocalizer(FaultLocalizerProtocol):
    def localize(
        self,
        context: FaultLocalizationContext,
        detection: Detection,
    ) -> FaultLocalizationResult:
        return FaultLocalizationResult(locations=[])
