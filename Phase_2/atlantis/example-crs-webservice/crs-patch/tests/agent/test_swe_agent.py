from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest
from python_aixcc_challenge.detection.models import AIxCCChallengeFullMode
from crete.atoms.action import HeadAction, NoPatchAction, UnknownErrorAction
from crete.atoms.detection import BlobInfo, Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.swe import SweAgent
from crete.framework.analyzer.services.crash_log import CrashLogAnalyzer
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.mock import MockEvaluator
from crete.framework.fault_localizer.models import FaultLocation
from crete.framework.fault_localizer.services.default import DefaultFaultLocalizer
from pytest_mock import MockerFixture
from python_llm.api.actors import LlmApiManager
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as SarifReport,
)


@pytest.fixture
def swe_agent() -> SweAgent:
    """Create a SweAgent instance for testing."""
    return SweAgent(
        fault_localizer=DefaultFaultLocalizer(),
        llm_api_manager=LlmApiManager.from_environment(model="gpt-4o"),
    )


@pytest.fixture
def mock_context() -> Mock:
    """Create a mock AgentContext."""
    context = MagicMock(spec=AgentContext)
    crash_log_analyzer = MagicMock(spec=CrashLogAnalyzer)
    crash_log_analyzer.analyze.return_value = (
        b"==ERROR: AddressSanitizer:\ntest crash log"
    )

    context_dict = {
        "crash_log_analyzer": crash_log_analyzer,
        "logger": Mock(),
        "evaluator": Mock(),
        "pool": Mock(),
    }
    context.__getitem__.side_effect = context_dict.__getitem__

    return context


@pytest.fixture
def mock_detection_only_blobs() -> Mock:
    """Create a mock Detection without SARIF report."""
    detection = Mock(spec=Detection)
    detection.mode = Mock(spec=AIxCCChallengeFullMode)
    detection.language = "c"
    detection.sarif_report = None
    detection.blobs = [
        BlobInfo(
            harness_name="test",
            sanitizer_name="test",
            blob=b"test",
        )
    ]
    return detection


@pytest.fixture
def mock_detection_sarif_and_blobs() -> Mock:
    """Create a mock Detection with SARIF report."""
    detection = Mock(spec=Detection)
    detection.mode = Mock(spec=AIxCCChallengeFullMode)
    detection.language = "c"
    detection.sarif_report = Mock(spec=SarifReport)
    detection.blobs = [
        BlobInfo(
            harness_name="test",
            sanitizer_name="test",
            blob=b"test",
        )
    ]
    return detection


@pytest.fixture
def mock_detection_only_sarif() -> Mock:
    """Create a mock Detection with only SARIF report."""
    detection = Mock(spec=Detection)
    detection.mode = Mock(spec=AIxCCChallengeFullMode)
    detection.language = "c"
    detection.sarif_report = Mock(spec=SarifReport)
    detection.blobs = []
    return detection


@pytest.mark.integration
@pytest.mark.vcr()
def test_mock_cp(detection_c_mock_cp_cpv_1: tuple[Path, Path]):
    swe_agent = SweAgent(
        fault_localizer=DefaultFaultLocalizer(),
        llm_api_manager=LlmApiManager.from_environment(model="gpt-4o"),
    )

    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    action = next(swe_agent.act(context, detection=detection))

    assert not isinstance(action, (UnknownErrorAction, NoPatchAction)), (
        f"Unexpected action: {action}"
    )


def test_get_base_prompt_only_blobs(
    swe_agent: SweAgent,
    mock_context: Mock,
    mock_detection_only_blobs: Mock,
    mocker: MockerFixture,
) -> None:
    """Test that the base prompt is generated correctly when there are only blobs."""
    fault_locations: list[FaultLocation] = []

    mock_instruction = mocker.patch(
        "crete.framework.agent.services.swe._make_default_instruction"
    )

    result = swe_agent._make_base_prompt(  # type: ignore[reportPrivateUsage]
        mock_context, mock_detection_only_blobs, fault_locations
    )

    assert result, "Result should not be empty"
    mock_instruction.assert_called_once()


def test_get_base_prompt_only_sarif_report(
    swe_agent: SweAgent,
    mock_context: Mock,
    mock_detection_only_sarif: Mock,
    mocker: MockerFixture,
) -> None:
    fault_locations: list[FaultLocation] = []
    mock_instruction = mocker.patch(
        "crete.framework.agent.services.swe._make_sarif_only_location_guided_instruction"
    )
    result = swe_agent._make_base_prompt(  # type: ignore[reportPrivateUsage]
        mock_context, mock_detection_only_sarif, fault_locations
    )

    assert result, "Result should not be empty"
    mock_instruction.assert_called_once()


def test_get_base_prompt_blobs_and_sarif_report(
    swe_agent: SweAgent,
    mock_context: Mock,
    mock_detection_sarif_and_blobs: Mock,
    mocker: MockerFixture,
) -> None:
    fault_locations: list[FaultLocation] = [
        Mock(
            spec=FaultLocation,
            line_range=(1234, 5678),
            file=Path("test_file.c"),
            function_name="test_function",
        )
    ]

    mocker.patch(
        "crete.framework.agent.services.swe._get_sarif_report",
        return_value="test_sarif_report",
    )

    mocker.patch(
        "crete.framework.agent.services.swe.get_code_block_from_file",
        return_value="test_code_block",
    )

    result = swe_agent._make_base_prompt(  # type: ignore[reportPrivateUsage]
        mock_context, mock_detection_sarif_and_blobs, fault_locations
    )

    assert result, "Result should not be empty"
    assert "test_code_block" in result, "test_code_block should be in the result"
    assert "test_function" in result, "test_function should be in the result"
    assert "test_sarif_report" in result, "test_sarif_report should be in the result"
