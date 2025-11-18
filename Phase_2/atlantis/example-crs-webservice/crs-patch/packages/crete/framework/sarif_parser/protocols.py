from typing import Protocol

from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as SarifReport,
    ReportingDescriptor as Rules,
    Location,
    Result,
)


class SarifParserProtocol(Protocol):
    """Protocol for parsing SARIF reports."""

    def get_locations(self, sarif_report: SarifReport) -> list[Location]: ...

    def get_result(self, sarif_report: SarifReport) -> Result: ...

    def get_rules(self, sarif_report: SarifReport) -> list[Rules]: ...

    # NOTE: This is Temporary function. because Orig said cwe can be multiple.
    # but in current status, we can't parse cwe from sarif report. (there is no cwe in sarif report)
    # so for now, we just use rule id as cwe id as libpng example. (rule id exists only one)
    def get_detected_rule(self, sarif_report: SarifReport) -> str: ...

    def get_vulnerability_description(self, sarif_report: SarifReport) -> str: ...
