from unittest.mock import MagicMock, Mock, patch

import pytest
from crete.atoms.action import (
    CompilableDiffAction,
    SoundDiffAction,
    UncompilableDiffAction,
    UnknownErrorAction,
    VulnerableDiffAction,
    WrongDiffAction,
)
from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.multi_retrieval.nodes.evaluators.docker_evaluator import (
    DockerEvaluator,
)
from crete.framework.agent.services.multi_retrieval.states.patch_state import (
    PatchAction,
    PatchState,
    PatchStatus,
)
from crete.framework.environment.exceptions import ChallengePoVFoundError
from python_aixcc_challenge.detection.models import (
    AIxCCChallengeDeltaMode,
    AIxCCChallengeFullMode,
)


@pytest.fixture
def docker_evaluator() -> DockerEvaluator:
    mock_docker_evaluator = DockerEvaluator()
    mock_docker_evaluator.context = MagicMock(spec=AgentContext)
    mock_docker_evaluator.detection = MagicMock(spec=Detection)
    mock_docker_evaluator.detection.blobs = []
    mock_docker_evaluator.detection.language = "c"
    mock_docker_evaluator.detection.sarif_report = None
    mock_docker_evaluator.detection.mode = Mock(spec=AIxCCChallengeFullMode)
    context_dict = {"evaluator": Mock(), "pool": Mock()}
    mock_docker_evaluator.context.__getitem__.side_effect = context_dict.__getitem__
    return mock_docker_evaluator


@pytest.fixture
def state() -> PatchState:
    return PatchState(
        patch_action=PatchAction.EVALUATE,
        patch_status=PatchStatus.INITIALIZED,
        messages=[],
        repo_path="/path/to/repo",
        diff="",
        n_evals=0,
        issue="test issue",
        retrieved=None,
    )


def test_set_context_and_detection(docker_evaluator: DockerEvaluator) -> None:
    mock_context = Mock(spec=AgentContext)
    mock_detection = Mock(spec=Detection)
    docker_evaluator.set_context_and_detection(mock_context, mock_detection)
    assert docker_evaluator.context == mock_context
    assert docker_evaluator.detection == mock_detection


def test_map_action_to_status(docker_evaluator: DockerEvaluator) -> None:
    patch_status = docker_evaluator._map_action_to_status(SoundDiffAction(diff=b""))  # type: ignore
    assert patch_status == PatchStatus.SOUND

    patch_status = docker_evaluator._map_action_to_status(  # type: ignore
        UncompilableDiffAction(diff=b"", stdout=b"", stderr=b"")
    )
    assert patch_status == PatchStatus.UNCOMPILABLE

    patch_status = docker_evaluator._map_action_to_status(  # type: ignore
        CompilableDiffAction(diff=b"", stdout=b"", stderr=b"")
    )
    assert patch_status == PatchStatus.COMPILABLE

    patch_status = docker_evaluator._map_action_to_status(  # type: ignore
        VulnerableDiffAction(diff=b"", stdout=b"", stderr=b"")
    )
    assert patch_status == PatchStatus.VULNERABLE

    patch_status = docker_evaluator._map_action_to_status(  # type: ignore
        WrongDiffAction(diff=b"", stdout=b"", stderr=b"")
    )
    assert patch_status == PatchStatus.WRONG

    patch_status = docker_evaluator._map_action_to_status(  # type: ignore
        UnknownErrorAction(error=Exception("error"))
    )
    assert patch_status == PatchStatus.UNKNOWN


def test_get_action_log(docker_evaluator: DockerEvaluator) -> None:
    action = VulnerableDiffAction(diff=b"", stdout=b"stdout", stderr=b"stderr")
    issue = docker_evaluator._get_action_log(action)  # type: ignore
    assert issue == "stdoutstderr"

    action = CompilableDiffAction(diff=b"", stdout=b"stdout", stderr=b"stderr")
    issue = docker_evaluator._get_action_log(action)  # type: ignore
    assert issue == "stdoutstderr"

    action = UncompilableDiffAction(diff=b"", stdout=b"stdout", stderr=b"stderr")
    issue = docker_evaluator._get_action_log(action)  # type: ignore
    assert issue == "stdoutstderr"

    action = WrongDiffAction(diff=b"", stdout=b"stdout", stderr=b"stderr")
    issue = docker_evaluator._get_action_log(action)  # type: ignore
    assert issue == "stdoutstderr"


def test_environment_run_pov_found(docker_evaluator: DockerEvaluator) -> None:
    docker_evaluator.context["pool"].restore = Mock()  # type: ignore
    docker_evaluator.context["pool"].restore.return_value.run_pov.side_effect = (  # type: ignore
        ChallengePoVFoundError(stdout=b"stdout", stderr=b"stderr")
    )
    action = docker_evaluator._environment_run_pov()  # type: ignore
    assert isinstance(action, VulnerableDiffAction)


def test_environment_run_pov_unknown(docker_evaluator: DockerEvaluator) -> None:
    docker_evaluator.context["pool"].restore = Mock()  # type: ignore
    docker_evaluator.context["pool"].restore.return_value.run_pov.side_effect = (  # type: ignore
        Exception("unknown error")
    )
    action = docker_evaluator._environment_run_pov()  # type: ignore
    assert isinstance(action, UnknownErrorAction)


def test_environment_run_pov_sound(docker_evaluator: DockerEvaluator) -> None:
    docker_evaluator.context["pool"].run_pov.return_value = None  # type: ignore
    action = docker_evaluator._environment_run_pov()  # type: ignore
    assert isinstance(action, SoundDiffAction)


def test_environment_run_pov_none_context(docker_evaluator: DockerEvaluator) -> None:
    docker_evaluator.context = None
    with pytest.raises(ValueError):
        docker_evaluator._environment_run_pov()  # type: ignore


def test_environment_run_pov_none_detection(docker_evaluator: DockerEvaluator) -> None:
    docker_evaluator.detection = None
    with pytest.raises(ValueError):
        docker_evaluator._environment_run_pov()  # type: ignore


def test_call_with_empty_diff(
    docker_evaluator: DockerEvaluator, state: PatchState
) -> None:
    docker_evaluator._environment_run_pov = Mock(  # type: ignore
        return_value=VulnerableDiffAction(diff=b"", stdout=b"stdout", stderr=b"stderr")
    )
    state.diff = ""
    result = docker_evaluator(state)
    assert result["patch_action"] == PatchAction.ANALYZE_ISSUE
    assert result["patch_status"] == PatchStatus.VULNERABLE
    assert result["n_evals"] == 1
    assert result["issue"] == "stdoutstderr"


def test_call_with_sound_diff(
    docker_evaluator: DockerEvaluator, state: PatchState
) -> None:
    docker_evaluator.context["evaluator"].evaluate = Mock(  # type: ignore
        return_value=SoundDiffAction(diff=b"sound diff")
    )
    docker_evaluator._environment_run_tests = Mock(  # type: ignore
        return_value=("tests log", PatchStatus.SOUND)
    )
    state.diff = "sound diff"
    result = docker_evaluator(state)
    assert result["patch_action"] == PatchAction.DONE
    assert result["patch_status"] == PatchStatus.SOUND
    assert result["n_evals"] == 1
    assert result["issue"] == ""


def test_call_with_sound_diff_tests_failed(
    docker_evaluator: DockerEvaluator, state: PatchState
) -> None:
    docker_evaluator.context["evaluator"].evaluate = Mock(  # type: ignore
        return_value=SoundDiffAction(diff=b"sound diff")
    )
    docker_evaluator._environment_run_tests = Mock(  # type: ignore
        return_value=("tests log", PatchStatus.TESTS_FAILED)
    )
    state.diff = "sound diff"
    result = docker_evaluator(state)
    assert result["patch_action"] == PatchAction.ANALYZE_ISSUE
    assert result["patch_status"] == PatchStatus.TESTS_FAILED
    assert result["n_evals"] == 1
    assert result["issue"] != ""


def test_call_with_unknown_error(
    docker_evaluator: DockerEvaluator, state: PatchState
) -> None:
    docker_evaluator.context["evaluator"].evaluate = Mock(  # type: ignore
        return_value=UnknownErrorAction(error=Exception("unknown error"))
    )
    state.diff = "test diff"
    result = docker_evaluator(state)
    assert result["patch_action"] == PatchAction.DONE
    assert result["patch_status"] == PatchStatus.UNKNOWN
    assert result["n_evals"] == 1
    assert result["issue"] == ""


def test_call_with_sarif_report(
    docker_evaluator: DockerEvaluator, state: PatchState
) -> None:
    docker_evaluator._environment_run_pov = Mock(  # type: ignore
        return_value=UnknownErrorAction(error=Exception("no pov"))
    )
    docker_evaluator._add_sarif_logs = Mock(  # type: ignore
        return_value="sarif logs"
    )
    docker_evaluator.detection.sarif_report = Mock()  # type: ignore
    state.diff = ""
    result = docker_evaluator(state)
    assert result["patch_action"] == PatchAction.ANALYZE_ISSUE
    assert result["patch_status"] == PatchStatus.VULNERABLE
    assert result["n_evals"] == 1
    assert result["issue"] == "sarif logs"


def test_call_with_max_evals(
    docker_evaluator: DockerEvaluator, state: PatchState
) -> None:
    docker_evaluator.context["evaluator"].evaluate = Mock(  # type: ignore
        return_value=VulnerableDiffAction(diff=b"", stdout=b"stdout", stderr=b"stderr")
    )
    docker_evaluator.max_n_evals = 3
    state.diff = "vulnerable diff"
    state.n_evals = 3
    result = docker_evaluator(state)
    assert result["patch_action"] == PatchAction.DONE
    assert result["patch_status"] == PatchStatus.VULNERABLE
    assert result["n_evals"] == 4
    assert result["issue"] == "stdoutstderr"


def test_call_with_analyze_issue(
    docker_evaluator: DockerEvaluator, state: PatchState
) -> None:
    docker_evaluator.context["evaluator"].evaluate = Mock(  # type: ignore
        return_value=VulnerableDiffAction(diff=b"", stdout=b"stdout", stderr=b"stderr")
    )
    state.n_evals = 1
    state.diff = "vulnerable diff"
    docker_evaluator.max_n_evals = 3
    result = docker_evaluator(state)
    assert result["patch_action"] == PatchAction.ANALYZE_ISSUE
    assert result["patch_status"] == PatchStatus.VULNERABLE
    assert result["n_evals"] == 2
    assert result["issue"] == "stdoutstderr"


def test_call_with_max_eval(
    docker_evaluator: DockerEvaluator, state: PatchState
) -> None:
    docker_evaluator.context["evaluator"].evaluate = Mock(  # type: ignore
        return_value=VulnerableDiffAction(diff=b"", stdout=b"stdout", stderr=b"stderr")
    )
    state.n_evals = 3
    state.diff = "vulnerable diff"
    docker_evaluator.max_n_evals = 4
    result = docker_evaluator(state)
    assert result["patch_action"] == PatchAction.DONE
    assert result["patch_status"] == PatchStatus.VULNERABLE
    assert result["n_evals"] == 4
    assert result["issue"] == "stdoutstderr"

    docker_evaluator._environment_run_tests = Mock(  # type: ignore
        return_value=("tests log", PatchStatus.TESTS_FAILED)
    )
    docker_evaluator.context["evaluator"].evaluate = Mock(  # type: ignore
        return_value=SoundDiffAction(diff=b"sound diff")
    )
    state.n_evals = 3
    state.diff = "diff"
    docker_evaluator.max_n_evals = 4
    result = docker_evaluator(state)
    assert result["patch_action"] == PatchAction.DONE
    assert result["patch_status"] == PatchStatus.TESTS_FAILED
    assert result["n_evals"] == 4
    assert result["tests_log"] == "tests log"


def test_add_sarif_logs_no_context_or_detection(
    docker_evaluator: DockerEvaluator,
) -> None:
    docker_evaluator.context = None
    result = docker_evaluator._add_sarif_logs("test log")  # type: ignore
    assert result == "test log"

    docker_evaluator.context = Mock()
    docker_evaluator.detection = None
    result = docker_evaluator._add_sarif_logs("test log")  # type: ignore
    assert result == "test log"


def test_add_sarif_logs_no_sarif_report(docker_evaluator: DockerEvaluator) -> None:
    docker_evaluator.detection.sarif_report = None  # type: ignore
    result = docker_evaluator._add_sarif_logs("test log")  # type: ignore
    assert result == "test log"


def test_add_sarif_logs_with_valid_sarif(docker_evaluator: DockerEvaluator) -> None:
    # Mock SARIF report structure
    mock_sarif_report = Mock()
    mock_run = Mock()
    mock_result = Mock()
    mock_sarif_report.runs = [mock_run]
    mock_run.results = [mock_result]
    docker_evaluator.detection.sarif_report = mock_sarif_report  # type: ignore
    docker_evaluator._format_sarif_result = Mock(return_value="formatted sarif result")  # type: ignore

    result = docker_evaluator._add_sarif_logs("test log")  # type: ignore
    assert result == "test log\nformatted sarif result"


def test_format_sarif_result_no_locations(docker_evaluator: DockerEvaluator) -> None:
    mock_result = Mock()
    mock_result.locations = None
    result = docker_evaluator._format_sarif_result(mock_result)  # type: ignore
    assert result == ""

    mock_result.locations = []
    result = docker_evaluator._format_sarif_result(mock_result)  # type: ignore
    assert result == ""


def test_format_sarif_result_with_physical_location(
    docker_evaluator: DockerEvaluator,
) -> None:
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

    result = docker_evaluator._format_sarif_result(mock_result)  # type: ignore
    assert "/path/to/file.c:10-15" in result
    assert "Test message" in result
    assert "error" in result
    assert "high" in result


def test_format_sarif_result_with_logical_locations(
    docker_evaluator: DockerEvaluator,
) -> None:
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

    result = docker_evaluator._format_sarif_result(mock_result)  # type: ignore
    assert "function_name(function)" in result


def test_add_related_diff(docker_evaluator: DockerEvaluator) -> None:
    assert docker_evaluator.detection is not None
    assert docker_evaluator.context is not None

    # detection mode is not AIxCCChallengeDeltaMode
    docker_evaluator.detection.mode = Mock()
    result = docker_evaluator._add_related_diff("test issue")  # type: ignore
    assert result == "test issue"

    docker_evaluator.max_n_log_chars = 500

    docker_evaluator.detection.mode = Mock(spec=AIxCCChallengeDeltaMode)
    with patch(
        "crete.framework.agent.services.multi_retrieval.nodes.evaluators.docker_evaluator.get_all_diff"
    ) as mock_get_diff:
        # get_all_diff raises exception
        mock_get_diff.side_effect = Exception("get_all_diff failed")
        result = docker_evaluator._add_related_diff("test issue")  # type: ignore
        assert result == "test issue"

    with patch(
        "crete.framework.agent.services.multi_retrieval.nodes.evaluators.docker_evaluator.get_all_diff"
    ) as mock_get_diff:
        # delta_diffs is None
        mock_get_diff.return_value = None
        result = docker_evaluator._add_related_diff("test issue")  # type: ignore
        assert result == "test issue"

        # delta_diffs is empty
        mock_get_diff.return_value = []
        result = docker_evaluator._add_related_diff("test issue")  # type: ignore
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
        result = docker_evaluator._add_related_diff("test issue")  # type: ignore
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
        result = docker_evaluator._add_related_diff("test issue")  # type: ignore
        assert "test issue" in result
        assert "--- a/file1.c\n+++ b/file1.c\n@@ -1,1 +1,2 @@" in result
        assert "--- a/file2.c\n+++ b/file2.c\n@@ -1,1 +1,2 @@" in result

        # long diff that exceeds max_n_log_chars
        docker_evaluator.max_n_log_chars = 100
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
        result = docker_evaluator._add_related_diff("test issue")  # type: ignore
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
        result = docker_evaluator._add_related_diff("test issue")  # type: ignore
        assert "--- a/file2.c\n+++ b/file2.c\n@@ -1,1 +1,2 @@" in result
