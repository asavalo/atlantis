from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.fault_localizer.models import FaultLocation
from crete.framework.fault_localizer.services.stacktrace import StacktraceFaultLocalizer

from tests.common.utils import mock_fault_localization_context


@pytest.mark.vcr()
def test_mock_cp(detection_c_mock_cp_cpv_0: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    assert StacktraceFaultLocalizer().localize(
        mock_fault_localization_context(context), detection
    ).locations == [
        FaultLocation(
            file=context["pool"].source_directory / "mock_vp.c",
            function_name="func_a",
            line_range=(12, 13),
        )
    ]


@pytest.mark.vcr()
def test_cp_java(detection_jvm_mock_java_cpv_0: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_jvm_mock_java_cpv_0,
        evaluator=DummyEvaluator(),
        max_timeout=60 * 60,  # Jenkins build takes about 30 minute
    ).build(
        previous_action=HeadAction(),
    )

    actual_faults = (
        StacktraceFaultLocalizer()
        .localize(mock_fault_localization_context(context), detection)
        .locations
    )

    expected_faults = [
        FaultLocation(
            file=context["pool"].source_directory
            / "src/main/java/com/aixcc/mock_java/App.java",
            function_name="executeCommand",
            line_range=(15, 16),
        ),
    ]

    assert actual_faults == expected_faults
