import copy
from pathlib import Path

import pytest
from crete.atoms.detection import Detection
from crete.commons.logging.hooks import use_logger
from crete.framework.fault_localizer import FaultLocalizationContext
from crete.framework.fault_localizer.services.sarif import SarifFaultLocalizer
from python_aixcc_challenge.detection.models import AIxCCChallengeFullMode
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as SarifReport,
)


@pytest.fixture
def mock_detection():
    detection = Detection(
        mode=AIxCCChallengeFullMode(
            base_ref="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        vulnerability_identifier="CWE-000",
        project_name="test_project",
        language="c",
        blobs=[],
        sarif_report=None,
    )
    return detection


@pytest.fixture
def mock_context():
    class MockPool:
        def __init__(self):
            self.source_directory = Path("tests/fault_localizer/test_data")

    return {
        "pool": MockPool(),
        "logger": use_logger(),
    }


SARIF_REPORT_NORMAL = {
    "runs": [
        {
            "artifacts": [{"location": {"index": 0, "uri": "src/core/ngx_cycle.c"}}],
            "automationDetails": {"id": "/"},
            "conversion": {"tool": {"driver": {"name": "GitHub Code Scanning"}}},
            "results": [
                {
                    "correlationGuid": "2bc26b18-b683-4874-be9e-06108b3bf333",
                    "level": "warning",
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "src/core/ngx_cycle.c",
                                },
                                "region": {
                                    "endColumn": 1,
                                    "endLine": 1677,
                                    "startColumn": 1,
                                    "startLine": 1656,
                                },
                            }
                        }
                    ],
                    "message": {
                        "text": "When remove first element from ngx_black_list_t, it may not remove double link. Then, try to remove another element from ngx_black_list_t, it may lead to use-after-free bug."
                    },
                    "partialFingerprints": {
                        "primaryLocationLineHash": "a17cbcafe13f3e5d:1"
                    },
                    "properties": {
                        "github/alertNumber": 2,
                        "github/alertUrl": "https://api.github.com/repos/aixcc-afc/round-exhibition2-sqlite/code-scanning/alerts/2",
                    },
                    "rule": {"id": "CWE-416", "index": 0},
                    "ruleId": "CWE-416",
                }
            ],
            "tool": {
                "driver": {
                    "name": "CodeScan++",
                    "rules": [
                        {
                            "defaultConfiguration": {"level": "warning"},
                            "fullDescription": {
                                "text": 'The product reuses or references memory after it has been freed. At some point afterward, the memory may be allocated again and saved in another pointer, while the original pointer references a location somewhere within the new allocation. Any operations using the original pointer are no longer valid because the memory "belongs" to the code that operates on the new pointer.'
                            },
                            "helpUri": "https://cwe.mitre.org/",
                            "id": "CWE-416",
                            "properties": {},
                            "shortDescription": {"text": "Use After Free"},
                        }
                    ],
                    "version": "1.0.0",
                }
            },
            "versionControlProvenance": [
                {
                    "branch": "refs/heads/challenges/nginx-source",
                    "repositoryUri": "https://github.com/aixcc-public/challenge-004-nginx-source",
                    "revisionId": "bc835aa15bc9da99d73822092df583e149bf19a9",
                }
            ],
        }
    ],
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
}

SARIF_REPORT_NO_RULE = copy.deepcopy(SARIF_REPORT_NORMAL)
SARIF_REPORT_NO_RULE["runs"][0]["results"][0].pop("rule")  # type: ignore
SARIF_REPORT_NO_END_LINE_RANGE = copy.deepcopy(SARIF_REPORT_NORMAL)
SARIF_REPORT_NO_END_LINE_RANGE["runs"][0]["results"][0]["locations"][0][  # type: ignore
    "physicalLocation"
]["region"].pop("endLine")  # type: ignore

success_test_data = {
    "normal": SARIF_REPORT_NORMAL,
    "no_rule": SARIF_REPORT_NO_RULE,
    "no_end_line_range": SARIF_REPORT_NO_END_LINE_RANGE,
}


@pytest.mark.slow
@pytest.mark.parametrize(
    "test_name",
    success_test_data,
)
def test_sarif_fault_localizer_success(
    detection_c_asc_nginx_cpv_0: tuple[Path, Path],
    mock_context: FaultLocalizationContext,
    mock_detection: Detection,
    test_name: str,
):
    mock_detection.sarif_report = SarifReport.model_validate(
        success_test_data[test_name]
    )
    mock_context["pool"].source_directory = detection_c_asc_nginx_cpv_0[0]

    fault_localization_result = SarifFaultLocalizer().localize(
        mock_context, mock_detection
    )

    assert fault_localization_result.description, "Description is not set"
    assert len(fault_localization_result.locations) == 1
    assert fault_localization_result.locations[0].file == Path("src/core/ngx_cycle.c")

    if test_name != "no_end_line_range":
        assert fault_localization_result.locations[0].line_range == (1656, 1677)
