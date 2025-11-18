from pathlib import Path

from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.sarif_parser.services.default import DefaultSarifParser
from sarif.sarif_model import Location


def test_sarif_parser(
    detection_c_mock_cp_cpv_0_sarif_only: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0_sarif_only,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )
    sarif_report = detection.sarif_report
    assert sarif_report is not None, "Sarif report is None"

    sarif_parser = DefaultSarifParser()
    locations: list[Location] = sarif_parser.get_locations(sarif_report)

    assert len(locations) != 0, "No locations found"
    context["logger"].info(locations)

    rule_id = sarif_parser.get_detected_rule(sarif_report)
    assert rule_id is not None, "Rule ID is None"
    context["logger"].info(rule_id)

    message = sarif_parser.get_vulnerability_description(sarif_report)
    assert message is not None, (
        "This sarif report must have message field, but sarif parser can't parse it"
    )
    context["logger"].info(f"Vulnerability description is: {message}")
