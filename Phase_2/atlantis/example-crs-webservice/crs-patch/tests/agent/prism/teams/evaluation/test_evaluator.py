from unittest.mock import MagicMock, Mock, patch

import pytest
from crete.atoms.action import (
    SoundDiffAction,
    UnknownErrorAction,
    VulnerableDiffAction,
)
from crete.atoms.detection import Detection
from crete.commons.interaction.exceptions import CommandInteractionError
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.prism.states.common_state import PatchStatus
from crete.framework.agent.services.prism.states.evaluation_team_state import (
    EvaluationTeamState,
)
from crete.framework.agent.services.prism.teams.evaluation.evaluator import Evaluator
from crete.framework.environment.exceptions import (
    ChallengePoVFoundError,
    ChallengeTestFailedError,
)
from python_aixcc_challenge.detection.models import (
    AIxCCChallengeDeltaMode,
    AIxCCChallengeFullMode,
)


@pytest.fixture
def evaluator() -> Evaluator:
    mock_evaluator = Evaluator(llm=Mock())
    mock_context = MagicMock(spec=AgentContext)
    mock_detection = MagicMock(spec=Detection)
    mock_detection.language = "c"
    mock_detection.sarif_report = None
    mock_detection.mode = Mock(spec=AIxCCChallengeFullMode)
    context_dict = {"evaluator": Mock(), "pool": Mock()}
    mock_context.__getitem__.side_effect = context_dict.__getitem__
    mock_evaluator.set_context_and_detection(mock_context, mock_detection)
    return mock_evaluator


@pytest.fixture
def state() -> EvaluationTeamState:
    return EvaluationTeamState()


def test_set_context_and_detection(evaluator: Evaluator) -> None:
    mock_context = Mock(spec=AgentContext)
    mock_detection = Mock(spec=Detection)
    evaluator.set_context_and_detection(mock_context, mock_detection)
    assert evaluator.context == mock_context
    assert evaluator.detection == mock_detection


def test_environment_run_pov(evaluator: Evaluator) -> None:
    # POV found
    evaluator.context["pool"].restore.return_value.run_pov.side_effect = (  # type: ignore
        ChallengePoVFoundError(stdout=b"stdout", stderr=b"stderr")
    )
    action = evaluator._environment_run_pov()  # type: ignore
    assert isinstance(action, VulnerableDiffAction)

    # POV unknown
    evaluator.context["pool"].restore = Mock()  # type: ignore
    evaluator.context["pool"].restore.return_value.run_pov.side_effect = (  # type: ignore
        Exception("unknown error")
    )
    action = evaluator._environment_run_pov()  # type: ignore
    assert isinstance(action, UnknownErrorAction)

    # POV none context
    evaluator.context = None
    with pytest.raises(ValueError):
        evaluator._environment_run_pov()  # type: ignore

    # POV non detection
    evaluator.detection = None
    with pytest.raises(ValueError):
        evaluator._environment_run_pov()  # type: ignore


def test_call_with_patch_status_initialized(
    evaluator: Evaluator, state: EvaluationTeamState
) -> None:
    state.patch_status = PatchStatus.INITIALIZED
    evaluator._environment_run_pov = Mock(  # type: ignore
        return_value=VulnerableDiffAction(diff=b"", stdout=b"stdout", stderr=b"stderr")
    )
    result = evaluator(state)
    assert result["patch_status"] == PatchStatus.VULNERABLE
    assert result["issue"] == "stdoutstderr"


def test_call_with_empty_diff(evaluator: Evaluator, state: EvaluationTeamState) -> None:
    state.patch_status = PatchStatus.VULNERABLE
    state.diff = ""
    result = evaluator(state)
    assert result["patch_status"] == PatchStatus.UNCOMPILABLE
    assert result["issue"] == "Patch not applicable due to empty diff"


def test_call_with_non_empty_diff(
    evaluator: Evaluator, state: EvaluationTeamState
) -> None:
    evaluator.context["evaluator"].evaluate = Mock(  # type: ignore
        return_value=SoundDiffAction(diff=b"sound diff")
    )
    evaluator._environment_run_tests = Mock(  # type: ignore
        return_value=("test result", PatchStatus.SOUND)
    )
    evaluator.context["pool"].restore = Mock()  # type: ignore
    state.diff = "sound diff"
    result = evaluator(state)
    assert result["patch_status"] == PatchStatus.SOUND
    assert result["issue"] == ""


def test_environment_run_tests_not_sound_patch(evaluator: Evaluator) -> None:
    tests_log, patch_status = evaluator._environment_run_tests(  # type: ignore
        "diff", PatchStatus.UNCOMPILABLE
    )
    assert tests_log == "Tests skipped. Provide a sound patch."
    assert patch_status == PatchStatus.UNCOMPILABLE


def test_environment_run_tests_no_tests_found(evaluator: Evaluator) -> None:
    evaluator.context["pool"].internal_test_exists.return_value = False  # type: ignore
    tests_log, patch_status = evaluator._environment_run_tests(  # type: ignore
        "diff", PatchStatus.SOUND
    )
    assert tests_log == "Tests skipped. No tests found."
    assert patch_status == PatchStatus.SOUND


def test_environment_run_tests_success(evaluator: Evaluator) -> None:
    evaluator.context["pool"].internal_test_exists.return_value = True  # type: ignore
    mock_environment = Mock()
    evaluator.context["pool"].restore.return_value = mock_environment  # type: ignore
    mock_environment.run_tests.return_value = (b"test output", b"")

    tests_log, patch_status = evaluator._environment_run_tests(  # type: ignore
        "diff", PatchStatus.SOUND
    )
    assert tests_log == b"test output"
    assert patch_status == PatchStatus.SOUND


def test_environment_run_tests_failure(evaluator: Evaluator) -> None:
    evaluator.context["pool"].internal_test_exists.return_value = True  # type: ignore
    mock_environment = Mock()
    evaluator.context["pool"].restore.return_value = mock_environment  # type: ignore
    mock_environment.run_tests.side_effect = ChallengeTestFailedError(
        stdout=b"test failed", stderr=b"error"
    )

    tests_log, patch_status = evaluator._environment_run_tests(  # type: ignore
        "diff", PatchStatus.SOUND
    )
    assert tests_log == "test failederror"
    assert patch_status == PatchStatus.TESTS_FAILED


def test_environment_run_tests_command_interaction_error(evaluator: Evaluator) -> None:
    evaluator.context["pool"].internal_test_exists.return_value = True  # type: ignore
    mock_environment = Mock()
    evaluator.context["pool"].restore.return_value = mock_environment  # type: ignore
    mock_environment.run_tests.side_effect = CommandInteractionError(  # type: ignore
        stdout=b"", stderr=b"interaction error", return_code=1
    )

    tests_log, patch_status = evaluator._environment_run_tests(  # type: ignore
        "diff", PatchStatus.SOUND
    )
    assert tests_log == "Command interaction error while testing."
    assert patch_status == PatchStatus.SOUND


def test_add_sarif_logs_no_context_or_detection(evaluator: Evaluator) -> None:
    evaluator.context = None
    result = evaluator._add_sarif_logs("test log")  # type: ignore
    assert result == "test log"

    evaluator.context = Mock()
    evaluator.detection = None
    result = evaluator._add_sarif_logs("test log")  # type: ignore
    assert result == "test log"


def test_add_sarif_logs_no_sarif_report(evaluator: Evaluator) -> None:
    evaluator.detection.sarif_report = None  # type: ignore
    result = evaluator._add_sarif_logs("test log")  # type: ignore
    assert result == "test log"


def test_add_sarif_logs_with_valid_sarif(evaluator: Evaluator) -> None:
    # Mock SARIF report structure
    mock_sarif_report = Mock()
    mock_run = Mock()
    mock_result = Mock()
    mock_sarif_report.runs = [mock_run]
    mock_run.results = [mock_result]
    evaluator.detection.sarif_report = mock_sarif_report  # type: ignore
    evaluator._format_sarif_result = Mock(return_value="formatted sarif result")  # type: ignore

    result = evaluator._add_sarif_logs("test log")  # type: ignore
    assert result == "test log\nformatted sarif result"


def test_format_sarif_result_no_locations(evaluator: Evaluator) -> None:
    mock_result = Mock()
    mock_result.locations = None
    result = evaluator._format_sarif_result(mock_result)  # type: ignore
    assert result == ""

    mock_result.locations = []
    result = evaluator._format_sarif_result(mock_result)  # type: ignore
    assert result == ""


def test_format_sarif_result_with_physical_location(evaluator: Evaluator) -> None:
    mock_result = Mock()
    mock_location = Mock()
    mock_physical_location = Mock()
    mock_artifact_location = Mock()

    mock_physical_location.root.artifactLocation = mock_artifact_location
    mock_artifact_location.uri = "/path/to/file.c"
    mock_physical_location.root.region.root.startLine = 10
    mock_physical_location.root.region.root.endLine = 15
    mock_location.physicalLocation = mock_physical_location
    mock_location.logicalLocations = None

    mock_result.message.root.text = "Test message"
    mock_result.kind = "error"
    mock_result.level = "high"

    mock_result.locations = [mock_location]

    result = evaluator._format_sarif_result(mock_result)  # type: ignore
    assert "/path/to/file.c:10-15" in result
    assert "Test message" in result
    assert "error" in result
    assert "high" in result


def test_format_sarif_result_with_logical_locations(evaluator: Evaluator) -> None:
    mock_result = Mock()
    mock_location = Mock()
    mock_logical_location = Mock()

    mock_logical_location.name = "function_name"
    mock_logical_location.kind = "function"
    mock_location.logicalLocations = [mock_logical_location]
    mock_location.physicalLocation = None

    mock_result.message.root.text = "Test message"
    mock_result.kind = None
    mock_result.level = None

    mock_result.locations = [mock_location]

    result = evaluator._format_sarif_result(mock_result)  # type: ignore
    assert "function_name(function)" in result


def test_add_related_diff(evaluator: Evaluator) -> None:
    assert evaluator.detection is not None
    assert evaluator.context is not None

    # detection mode is not AIxCCChallengeDeltaMode
    evaluator.detection.mode = Mock()
    result = evaluator._add_related_diff("test issue")  # type: ignore
    assert result == "test issue"

    evaluator.max_n_log_chars = 500

    evaluator.detection.mode = Mock(spec=AIxCCChallengeDeltaMode)
    with patch(
        "crete.framework.agent.services.prism.teams.evaluation.evaluator.get_all_diff"
    ) as mock_get_diff:
        # get_all_diff raises exception
        mock_get_diff.side_effect = Exception("get_all_diff failed")
        result = evaluator._add_related_diff("test issue")  # type: ignore
        assert result == "test issue"

    with patch(
        "crete.framework.agent.services.prism.teams.evaluation.evaluator.get_all_diff"
    ) as mock_get_diff:
        # delta_diffs is None
        mock_get_diff.return_value = None
        result = evaluator._add_related_diff("test issue")  # type: ignore
        assert result == "test issue"

        # delta_diffs is empty
        mock_get_diff.return_value = []
        result = evaluator._add_related_diff("test issue")  # type: ignore
        assert result == "test issue"

        # valid delta_diffs but all contain "aixcc"
        mock_get_diff.return_value = [
            (
                "commit1",
                """diff --git
index text
--- a/.aixcc/file1.c
+++ b/.aixcc/file1.c
@@ -1,1 +1,2 @@
-changes1
+changes2-1
+changes2-2
""",
            ),
            (
                "commit2",
                """diff --git
index text
@@ -1,1 +1,2 @@
--- a/.aixcc/file2.c
+++ b/.aixcc/file2.c
-changes1
+changes2-1
+changes2-2
""",
            ),
        ]
        result = evaluator._add_related_diff("test issue")  # type: ignore
        assert result == "test issue"

        # valid delta_diffs
        mock_get_diff.return_value = [
            (
                "commit1",
                """diff --git
index text
--- a/file1.c
+++ b/file1.c
@@ -1,1 +1,2 @@
-changes1
+changes2-1
+changes2-2
""",
            ),
            (
                "commit2",
                """diff --git
index text
--- a/file2.c
+++ b/file2.c
@@ -1,1 +1,2 @@
-changes1
+changes2-1
+changes2-2
""",
            ),
        ]
        result = evaluator._add_related_diff("test issue")  # type: ignore
        assert "test issue" in result
        assert "--- a/file1.c\n+++ b/file1.c\n@@ -1,1 +1,2 @@" in result
        assert "--- a/file2.c\n+++ b/file2.c\n@@ -1,1 +1,2 @@" in result

        # long diff that exceeds max_n_log_chars
        evaluator.max_n_log_chars = 100
        long_diff = "a" * 100
        mock_get_diff.return_value = [
            (
                "commit1",
                f"""diff --git
index text
--- a/file1.c
+++ b/file1.c
@@ -1,1 +1,1 @@
-changes1
+{long_diff}
""",
            )
        ]
        result = evaluator._add_related_diff("test issue")  # type: ignore
        assert "--- a/file1.c\n+++ b/file1.c\n@@ -1,1 +1,1 @@" in result
        assert "..." in result

        # long diff and headers in abbreviated part
        mock_get_diff.return_value.append(
            (
                "commit2",
                """diff --git
index text
--- a/file2.c
+++ b/file2.c
@@ -1,1 +1,2 @@
-changes1
+changes2-1
+changes2-2
""",
            )
        )
        result = evaluator._add_related_diff("test issue")  # type: ignore
        assert "--- a/file2.c\n+++ b/file2.c\n@@ -1,1 +1,2 @@" in result
