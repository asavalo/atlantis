from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as SarifReport,
)
from sarif.sarif_model import Location, Result
from sarif.sarif_model import ReportingDescriptor as Rules

# NOTE: We assume that sarif report have only one run and one result
# IF we need to support multiple runs and results, we need to change the code


def _validate_sarif_report(sarif_report: SarifReport) -> tuple[bool, str]:
    if not sarif_report.runs:
        return False, "sarif.runs"
    if not sarif_report.runs[0].results:
        return False, "sarif.runs[0].results"
    if not sarif_report.runs[0].results[0].locations:
        return False, "sarif.runs[0].results[0].locations"
    return True, ""


def _validate_location(location: Location) -> tuple[bool, str]:
    if not location.physicalLocation:
        return False, "location.physicalLocation"

    # Check if we have a PhysicalLocation1 or PhysicalLocation2
    if not hasattr(location.physicalLocation.root, "artifactLocation"):
        return False, "location.physicalLocation.artifactLocation"

    if not location.physicalLocation.root:
        return False, "location.physicalLocation.root"
    if not location.physicalLocation.root.artifactLocation:  # type: ignore
        return False, "location.physicalLocation.artifactLocation"
    if not location.physicalLocation.root.artifactLocation.uri:  # type: ignore
        return False, "location.physicalLocation.artifactLocation.uri"
    if not location.physicalLocation.root.region.root:  # type: ignore
        return False, "location.physicalLocation.root.region.root"
    if not location.physicalLocation.root.region.root.startLine:  # type: ignore
        return False, "location.physicalLocation.root.region.root.startLine"
    return True, ""


def _validate_locations(locations: list[Location]) -> tuple[bool, str, int]:
    for location_index, location in enumerate(locations):
        is_valid, missing_fieldname = _validate_location(location)
        if not is_valid:
            return False, missing_fieldname, location_index
    return True, "", 0


def _validate_and_get_rule_id(result: Result) -> tuple[str | None, str]:
    return_rule_str = None
    err_str = ""
    if result.rule:
        if result.rule.root:
            if result.rule.root.id:
                return_rule_str = result.rule.root.id
            else:
                err_str = "result.rule.root.id"
        else:
            err_str = "result.rule.root"
    else:
        err_str = "result.rule"

    if result.ruleId:
        return_rule_str = result.ruleId
        err_str = ""
    else:
        err_str = "result.ruleId"

    return return_rule_str, err_str


def get_locations(sarif_report: SarifReport) -> list[Location]:
    is_valid, missing_fieldname = _validate_sarif_report(sarif_report)
    if not is_valid:
        raise ValueError(f"SARIF report is invalid: {missing_fieldname}")

    report_result: Result = sarif_report.runs[0].results[0]  # type: ignore
    locations: list[Location] = report_result.locations  # type: ignore

    is_valid, missing_fieldname, err_location_index = _validate_locations(locations)
    if not is_valid:
        raise ValueError(
            f"Locations is invalid: {err_location_index}: {missing_fieldname}"
        )

    return locations


def get_result(sarif_report: SarifReport) -> Result:
    is_valid, missing_fieldname = _validate_sarif_report(sarif_report)
    if not is_valid:
        raise ValueError(f"SARIF report is invalid: {missing_fieldname}")

    return sarif_report.runs[0].results[0]  # type: ignore


def get_rules(sarif_report: SarifReport) -> list[Rules]:
    if not sarif_report.runs[0].results[0].rule:  # type: ignore
        raise ValueError("SARIF report invalid: sarif.runs[0].results[0].rule")
    if not sarif_report.runs[0].tool:  # type: ignore
        raise ValueError("SARIF report invalid: sarif.runs[0].tool")
    if not sarif_report.runs[0].tool.driver:  # type: ignore
        raise ValueError("SARIF report invalid: sarif.runs[0].tool.driver")
    if not sarif_report.runs[0].tool.driver.rules:  # type: ignore
        raise ValueError("SARIF report invalid: sarif.runs[0].tool.driver.rules")

    return sarif_report.runs[0].tool.driver.rules  # type: ignore


def get_detected_rule(sarif_report: SarifReport) -> str:
    result = get_result(sarif_report)
    rule_id, missing_fieldname = _validate_and_get_rule_id(result)  # type: ignore
    if rule_id is None:
        raise ValueError(f"Rule is invalid: {missing_fieldname}")

    return str(rule_id)


def get_vulnerability_description(sarif_report: SarifReport) -> str:
    result = get_result(sarif_report)
    if result.message and result.message.root and result.message.root.text:
        return result.message.root.text
    raise ValueError("Sarif data has no message field")
