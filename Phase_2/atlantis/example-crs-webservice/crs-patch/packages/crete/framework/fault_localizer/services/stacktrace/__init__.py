import os
from pathlib import Path

from crete.atoms.detection import Detection
from crete.commons.crash_analysis import get_crash_stacks
from crete.commons.crash_analysis.types import CrashStacks
from crete.framework.fault_localizer.contexts import FaultLocalizationContext
from crete.framework.fault_localizer.models import (
    FaultLocalizationResult,
    FaultLocation,
)
from crete.framework.fault_localizer.protocols import FaultLocalizerProtocol


class StacktraceFaultLocalizer(FaultLocalizerProtocol):
    def localize(
        self,
        context: FaultLocalizationContext,
        detection: Detection,
    ) -> FaultLocalizationResult:
        if (crash_stacks := get_crash_stacks(context, detection)) is None:
            return FaultLocalizationResult(locations=[])

        fault_locations = fault_locations_from_crash_stacks(crash_stacks)
        assert len(fault_locations) > 0, "No fault location found in crash stacks"
        return FaultLocalizationResult(locations=fault_locations)


def fault_locations_from_crash_stacks(
    crash_stacks: CrashStacks,
) -> list[FaultLocation]:
    first_stack = crash_stacks[0]
    frames = first_stack.frames[first_stack.sanitizer_index :]
    return [
        FaultLocation(
            file=Path(os.path.normpath(frame.file)),
            function_name=frame.function_name,
            # From 1-indexed to 0-indexed
            line_range=(frame.line - 1, frame.line),
        )
        for frame in frames
    ]
