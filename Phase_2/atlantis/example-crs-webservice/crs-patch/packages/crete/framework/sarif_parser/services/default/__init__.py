from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as SarifReport,
    ReportingDescriptor as Rules,
    Location,
    Result,
)
from crete.framework.sarif_parser.protocols import SarifParserProtocol
from crete.framework.sarif_parser.functions import (
    get_locations,
    get_result,
    get_rules,
    get_detected_rule,
    get_vulnerability_description,
)


class DefaultSarifParser(SarifParserProtocol):
    def get_locations(self, sarif_report: SarifReport) -> list[Location]:
        return get_locations(sarif_report)

    def get_result(self, sarif_report: SarifReport) -> Result:
        return get_result(sarif_report)

    def get_rules(self, sarif_report: SarifReport) -> list[Rules]:
        return get_rules(sarif_report)

    def get_detected_rule(self, sarif_report: SarifReport) -> str:
        return get_detected_rule(sarif_report)

    def get_vulnerability_description(self, sarif_report: SarifReport) -> str:
        return get_vulnerability_description(sarif_report)
