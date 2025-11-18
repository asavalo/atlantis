from unittest.mock import Mock

import pytest
from crete.framework.agent.services.multi_retrieval.states.patch_state import (
    CodeSnippet,
)
from crete.framework.agent.services.prism.states.patch_team_state import (
    PatchTeamState,
)
from crete.framework.agent.services.prism.teams.patch.patch_reviewer import (
    PatchReviewer,
)
from langchain_core.messages import AIMessage


@pytest.fixture
def patch_reviewer() -> PatchReviewer:
    mock_patch_reviewer = PatchReviewer(llm=Mock())
    mock_patch_reviewer.llm.invoke = Mock(
        return_value=AIMessage(content="test content")
    )
    return mock_patch_reviewer


@pytest.fixture
def state() -> PatchTeamState:
    return PatchTeamState()


def test_basic_call(patch_reviewer: PatchReviewer, state: PatchTeamState) -> None:
    state.diff = ""
    state.n_reviews = 0
    res = patch_reviewer(state)
    assert res["patch_review"] == patch_reviewer.empty_patch_message
    assert res["passed_checks"] is False
    assert res["n_reviews"] == 1

    state.diff = """\
--- a/file1.py
+++ b/file1.py
@@ -1,3 +1,2 @@
-line 1-1
-line 1-2
+patched code
 line 1-3"""
    state.applied_patches = [CodeSnippet()]
    state.n_reviews = 0
    patch_reviewer.llm.invoke = Mock(
        return_value=AIMessage(content="<verdict>\nThe patches are valid.\n</verdict>")
    )
    res = patch_reviewer(state)
    assert res["patch_review"] != patch_reviewer.empty_patch_message
    assert res["passed_checks"] is True
    assert res["n_reviews"] == 1

    patch_reviewer.llm.invoke = Mock(
        return_value=AIMessage(
            content="<verdict>\nThe patches are invalid.\n</verdict>"
        )
    )
    state.n_reviews = 0
    res = patch_reviewer(state)
    assert res["patch_review"] != patch_reviewer.empty_patch_message
    assert res["passed_checks"] is False
    assert res["n_reviews"] == 1
