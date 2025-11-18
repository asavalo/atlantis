from pathlib import Path
from typing import Any, Tuple

import pytest
from crete.atoms.action import HeadAction
from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.fault_localizer.models import FaultLocation
from crete.framework.fault_localizer.services.coderover_k import (
    CodeRoverKFaultLocalizer,
)
from pytest_mock.plugin import MockerFixture
from python_llm.api.actors import LlmApiManager

from tests.common.utils import mock_fault_localization_context


@pytest.fixture
def setup_context_detection(
    detection_c_mock_c_cpv_0: Tuple[Path, Path],
) -> Tuple[AgentContext, Detection]:
    """Set up context and detection for tests."""
    return AIxCCContextBuilder(
        *detection_c_mock_c_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )


@pytest.fixture
def rover() -> CodeRoverKFaultLocalizer:
    """Create a CodeRoverKFaultLocalizer instance with the specified model."""
    return CodeRoverKFaultLocalizer(
        analysis_llm=LlmApiManager.from_environment(model="gpt-4o"),
        parsing_llm=LlmApiManager.from_environment(model="gpt-4o"),
    )


@pytest.mark.skip(reason="Needs to update for new mock-c")
@pytest.mark.vcr()
@pytest.mark.parametrize(
    "report,expected_fault_location",
    [
        (
            """This is a test report with valid function name and file path.
        **File Path**: `/src/mock-c/mock.c`
        **Function Name**: `process_input_header`
        """,
            FaultLocation(Path("mock.c"), "process_input_header", None),
        ),
        (
            """This is a test report with valid function name but invalid file path.
        **File Path**: `/some/random/path`
        **Function Name**: `process_input_header`
        """,
            FaultLocation(Path("mock.c"), "process_input_header", None),
        ),
        (
            """This is a test report with wrong format.
        **File Path**: `/src/mock-c/mock.c`
        **Buggy Function**: `process_input_header`
        """,
            FaultLocation(Path("mock.c"), "process_input_header", None),
        ),
    ],
)
def test_parse_fault_location(
    setup_context_detection: Tuple[AgentContext, Detection],
    rover: CodeRoverKFaultLocalizer,
    report: str,
    expected_fault_location: FaultLocation | None,
):
    context, detection = setup_context_detection

    fault_location = rover._parse_fault_location(  # pyright: ignore[reportPrivateUsage]
        mock_fault_localization_context(context), detection, report
    )
    context["logger"].info(f"fault_location: {fault_location}")

    if expected_fault_location is not None:
        expected_fault_location.file = (
            context["pool"].source_directory / expected_fault_location.file
        )

    if fault_location is not None:
        assert fault_location == expected_fault_location


@pytest.mark.vcr()
def test_parse_fault_location_when_structured_output_returns_none(
    setup_context_detection: Tuple[AgentContext, Detection],
    rover: CodeRoverKFaultLocalizer,
    mocker: MockerFixture,
):
    def mock_chat_model_with_structured_output_returns_none(
        *args: Any, **kwargs: Any
    ) -> Any:
        class MockInvoke:
            def invoke(self, *args: Any, **kwargs: Any) -> None:
                return None

        return MockInvoke()

    mocker.patch(
        "langchain_core.language_models.chat_models.BaseChatModel.with_structured_output",
        mock_chat_model_with_structured_output_returns_none,
    )

    context, detection = setup_context_detection

    fault_location = rover._parse_fault_location(  # pyright: ignore[reportPrivateUsage]
        mock_fault_localization_context(context),
        detection,
        "Yes, this confirms my analysis.",
    )

    assert fault_location is None
