from pathlib import Path

from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as SarifReport,
)
from sarif.sarif_model import Location, Result

from crete.atoms.detection import Detection
from crete.framework.fault_localizer.contexts import FaultLocalizationContext
from crete.framework.fault_localizer.models import (
    FaultLocalizationResult,
    FaultLocation,
)
from crete.framework.fault_localizer.protocols import FaultLocalizerProtocol
from crete.framework.sarif_parser.services.default import DefaultSarifParser


class SarifFaultLocalizer(FaultLocalizerProtocol):
    def __init__(self):
        self._sarif_parser = DefaultSarifParser()

    def localize(
        self,
        context: FaultLocalizationContext,
        detection: Detection,
    ) -> FaultLocalizationResult:
        sarif_report: SarifReport | None = detection.sarif_report
        assert sarif_report is not None, "Sarif report is None"

        try:
            fault_locations = self._fault_locations_from_sarif_report(
                context, sarif_report
            )
        except Exception as e:
            context["logger"].error(f"Error parsing SARIF report: {e}")
            return FaultLocalizationResult(locations=[])

        try:
            description = self._description_from_sarif_report(context, sarif_report)
        except Exception as e:
            context["logger"].error(f"Error parsing SARIF description: {e}")
            description = None

        context["logger"].info(f"Found {len(fault_locations)} fault locations")
        return FaultLocalizationResult(
            locations=fault_locations, description=description
        )

    def _description_from_sarif_report(
        self, context: FaultLocalizationContext, sarif_report: SarifReport
    ) -> str:
        result: Result = self._sarif_parser.get_result(sarif_report)
        return str(result.message.root.text)  # type: ignore

    def _fault_locations_from_sarif_report(
        self, context: FaultLocalizationContext, sarif_report: SarifReport
    ) -> list[FaultLocation]:
        locations: list[Location] = self._sarif_parser.get_locations(sarif_report)
        fault_locations: list[FaultLocation] = []
        for location in locations:
            file_path = _file_path(location)
            line_range = _line_range(location)
            function_name = _function_name(location)

            # file_path is required and must exist
            if (
                file_path is None
                or not (context["pool"].source_directory / file_path).exists()
            ):
                continue

            fault_location = FaultLocation(
                file=Path(file_path),
                function_name=function_name,
                line_range=line_range,
            )
            fault_locations.append(fault_location)
        return fault_locations


def _file_path(location: Location) -> str | None:
    try:
        return str(location.physicalLocation.root.artifactLocation.uri)  # type: ignore
    except Exception:
        return None


def _line_range(location: Location) -> tuple[int, int] | None:
    try:
        start_line: int = int(location.physicalLocation.root.region.root.startLine)  # type: ignore
        if isinstance(location.physicalLocation.root.region.root.endLine, int):  # type: ignore
            end_line: int = int(location.physicalLocation.root.region.root.endLine)  # type: ignore
        else:
            end_line: int = start_line
        return (start_line, end_line)
    except Exception:
        return None


def _function_name(location: Location) -> str | None:
    try:
        if location.logicalLocations:
            for logical_location in location.logicalLocations:
                if logical_location.kind == "function":
                    return str(logical_location.name)  # type: ignore
    except Exception:
        pass
    return None
