from crete.atoms.action import (
    CompilableDiffAction,
    SoundDiffAction,
    UncompilableDiffAction,
    UnknownErrorAction,
    VulnerableDiffAction,
    WrongDiffAction,
)
from crete.framework.agent.services.prism.states.common_state import (
    CommonState,
    PatchStatus,
)


def test_patch_status_from_action() -> None:
    patch_status = PatchStatus.from_action(SoundDiffAction(diff=b""))  # type: ignore
    assert patch_status == PatchStatus.SOUND

    patch_status = PatchStatus.from_action(
        UncompilableDiffAction(diff=b"", stdout=b"", stderr=b"")
    )
    assert patch_status == PatchStatus.UNCOMPILABLE

    patch_status = PatchStatus.from_action(
        CompilableDiffAction(diff=b"", stdout=b"", stderr=b"")
    )
    assert patch_status == PatchStatus.COMPILABLE

    patch_status = PatchStatus.from_action(
        VulnerableDiffAction(diff=b"", stdout=b"", stderr=b"")
    )
    assert patch_status == PatchStatus.VULNERABLE

    patch_status = PatchStatus.from_action(
        WrongDiffAction(diff=b"", stdout=b"", stderr=b"")
    )
    assert patch_status == PatchStatus.WRONG

    patch_status = PatchStatus.from_action(UnknownErrorAction(error=Exception("error")))
    assert patch_status == PatchStatus.UNKNOWN


def test_common_state_from_common_state() -> None:
    original_common_state = CommonState(
        analysis_report="test report1",
        evaluation_report="test report2",
        diff="test diff",
        issue="test issue",
        repo_path="test repo",
    )
    common_state = CommonState.from_common_state(original_common_state)
    assert common_state.analysis_report == original_common_state.analysis_report
    assert common_state.evaluation_report == original_common_state.evaluation_report
    assert common_state.diff == original_common_state.diff
    assert common_state.issue == original_common_state.issue
    assert common_state.repo_path == original_common_state.repo_path
