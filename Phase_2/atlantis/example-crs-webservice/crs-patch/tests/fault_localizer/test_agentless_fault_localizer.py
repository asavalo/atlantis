# pyright: reportPrivateUsage=false
from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.fault_localizer.contexts import FaultLocalizationContext
from crete.framework.fault_localizer.models import FaultLocation
from crete.framework.fault_localizer.services.agentless import (
    AgentlessFaultLocalizer,
    _RelatedElement,
    _response_to_edit_locations,
)
from python_llm.api.actors import LlmApiManager

from tests.common.utils import mock_fault_localization_context


def _get_intermediate_data_for_mock_cp(
    context: FaultLocalizationContext,
) -> tuple[Path, list[Path], dict[Path, list[_RelatedElement]]]:
    target_file = context["pool"].source_directory / "mock_vp.c"
    suspicious_files = [target_file]
    related_elements_by_path = {
        target_file: [
            _RelatedElement(
                type="function",
                value="func_a",
                file=target_file,
            )
        ]
    }

    return target_file, suspicious_files, related_elements_by_path


def _check_fault_locations_for_mock_cp(
    context: FaultLocalizationContext,
    fault_locations: list[FaultLocation],
):
    BUGGY_LINE = 13

    result = any(
        (BUGGY_LINE in range(*fault_location.line_range))
        for fault_location in fault_locations
        if fault_location.file == context["pool"].source_directory / "mock_vp.c"
        and fault_location.function_name == "func_a"
        and fault_location.line_range
    )

    if not result:
        context["logger"].warning(
            "Fault locations:\n"
            + "\n".join(
                f"\t{fault_location.file}:{fault_location.function_name}:{fault_location.line_range}"
                for fault_location in fault_locations
            )
        )

    assert result


@pytest.mark.vcr()
def test_localize_to_suspicious_files(
    detection_c_mock_cp_cpv_0: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    files = AgentlessFaultLocalizer(
        LlmApiManager.from_environment(model="gpt-4o"),
    )._localize_to_suspicious_files(context, detection)

    assert any(file == context["pool"].source_directory / "mock_vp.c" for file in files)


@pytest.mark.vcr()
def test_localize_to_related_elements_by_path(
    detection_c_mock_cp_cpv_0: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    _, suspicious_files, expected_related_elements_by_path = (
        _get_intermediate_data_for_mock_cp(context)
    )

    actual_related_elements_by_path = AgentlessFaultLocalizer(
        LlmApiManager.from_environment(model="gpt-4o"),
    )._localize_to_related_elements_by_path(context, detection, suspicious_files)

    assert any(
        [
            related_element in expected_related_elements_by_path[file]
            for file, related_elements in actual_related_elements_by_path.items()
            for related_element in related_elements
        ]
    )


@pytest.mark.vcr()
def test_localize_to_edit_locations(
    detection_c_mock_cp_cpv_0: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    _, suspicious_files, related_elements_by_path = _get_intermediate_data_for_mock_cp(
        context
    )

    fault_locations = AgentlessFaultLocalizer(
        LlmApiManager.from_environment(model="gpt-4o"),
    )._localize_to_edit_locations(
        context,
        detection,
        suspicious_files,
        related_elements_by_path,
    )

    _check_fault_locations_for_mock_cp(context, fault_locations)


@pytest.mark.skip(reason="this test is so flaky")
def test_end_to_end(
    detection_c_mock_cp_cpv_0: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    fault_locations = (
        AgentlessFaultLocalizer(LlmApiManager.from_environment(model="gpt-4o"))
        .localize(mock_fault_localization_context(context), detection)
        .locations
    )

    _check_fault_locations_for_mock_cp(context, fault_locations)


@pytest.mark.vcr()
def test_response_to_edit_locations(
    detection_c_mock_cp_cpv_0: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(previous_action=HeadAction())

    response = """
    /src/fuzz/../mock-cp-src/mock_vp.c
    lines: 3-5
    lines: 10-16
    """

    _, suspicious_files, related_elements_by_path = _get_intermediate_data_for_mock_cp(
        context
    )

    fault_locations = _response_to_edit_locations(
        context,
        response,
        suspicious_files,
        related_elements_by_path,
    )

    _check_fault_locations_for_mock_cp(context, fault_locations)
