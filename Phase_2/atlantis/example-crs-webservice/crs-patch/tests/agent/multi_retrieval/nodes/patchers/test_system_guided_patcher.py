import inspect
import os
import tempfile
from unittest.mock import Mock

import pytest
from crete.framework.agent.services.multi_retrieval.nodes.patchers.system_guided_patcher import (
    SystemGuidedPatcher,
)
from crete.framework.agent.services.multi_retrieval.states.patch_state import (
    PatchAction,
    PatchState,
    PatchStatus,
)
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage


@pytest.fixture
def system_guided_patcher() -> SystemGuidedPatcher:
    mock_system_guided_patcher = SystemGuidedPatcher(llm=Mock())
    mock_system_guided_patcher.llm.invoke = Mock(
        return_value=AIMessage(content="test content")
    )
    return mock_system_guided_patcher


@pytest.fixture
def state() -> PatchState:
    return PatchState(
        patch_action=PatchAction.ANALYZE_ISSUE,
        patch_status=PatchStatus.VULNERABLE,
        messages=[],
        repo_path="/path/to/repo",
        diff="",
        n_evals=1,
        issue="test issue",
        retrieved=None,
    )


def test_issue_none(
    system_guided_patcher: SystemGuidedPatcher, state: PatchState
) -> None:
    state.issue = None
    with pytest.raises(ValueError):
        system_guided_patcher(state)


def test_analyze_issue(
    system_guided_patcher: SystemGuidedPatcher, state: PatchState
) -> None:
    state.issue = "test issue"
    state.patch_action = PatchAction.ANALYZE_ISSUE
    system_guided_patcher.system_prompt = "test system prompt"
    system_guided_patcher.initial_issue_prompt = "initial: {issue}"
    system_guided_patcher.feedback_issue_prompt = "feedback: {issue}"
    result = system_guided_patcher(state)
    assert result["patch_action"] == PatchAction.RETRIEVE
    assert len(result["messages"]) == 3
    assert isinstance(result["messages"][0], SystemMessage)
    assert isinstance(result["messages"][1], HumanMessage)
    assert isinstance(result["messages"][2], AIMessage)
    assert result["messages"][1].content == "initial: test issue"

    state.issue = "test issue"
    state.patch_action = PatchAction.ANALYZE_ISSUE
    result = system_guided_patcher(state)
    assert result["patch_action"] == PatchAction.RETRIEVE
    assert len(result["messages"]) == 5
    assert isinstance(result["messages"][3], HumanMessage)
    assert isinstance(result["messages"][4], AIMessage)
    assert result["messages"][3].content == "feedback: test issue"


def test_retrieve(
    system_guided_patcher: SystemGuidedPatcher, state: PatchState
) -> None:
    state.patch_action = PatchAction.RETRIEVE
    state.messages = [
        SystemMessage(content="test content"),
        HumanMessage(content="test"),
        AIMessage(content="<retrievals>\nretrieve\n</retrievals>"),
    ]
    state.retrieved = None
    system_guided_patcher.code_retriever_subgraph.retrieve_from_content = Mock(
        return_value="sample code"
    )
    result = system_guided_patcher(state)
    assert len(result["messages"]) == 3
    assert result["patch_action"] == PatchAction.RETRIEVE

    system_guided_patcher.llm.invoke = Mock(
        return_value=AIMessage(content="<retrievals>\nretrieve\n</retrievals>")
    )
    result = system_guided_patcher(state)
    assert len(result["messages"]) == 5
    assert result["patch_action"] == PatchAction.RETRIEVE
    assert system_guided_patcher.code_retriever_subgraph.retrieve_from_content.called


def test_retrieve_with_retry(
    system_guided_patcher: SystemGuidedPatcher, state: PatchState
) -> None:
    state.patch_action = PatchAction.RETRIEVE
    state.messages = [
        SystemMessage(content="test content"),
        HumanMessage(content="test"),
        AIMessage(content="retrieve"),
    ]
    state.retrieved = None
    system_guided_patcher.code_retriever_subgraph.retrieve_from_content = Mock(
        return_value="sample code"
    )
    system_guided_patcher.llm.invoke = Mock(
        side_effect=[
            AIMessage(content="retry"),
            AIMessage(content="<retrievals>\nretrieve\n</retrievals>"),
        ]
    )
    result = system_guided_patcher(state)
    assert len(result["messages"]) == 7
    assert result["patch_action"] == PatchAction.RETRIEVE


def test_patch(system_guided_patcher: SystemGuidedPatcher, state: PatchState) -> None:
    state.patch_action = PatchAction.RETRIEVE
    state.messages = [
        SystemMessage(content="test content"),
        HumanMessage(content="test"),
        AIMessage(content="test"),
    ]
    state.retrieved = "test retrieved"
    system_guided_patcher.llm.invoke = Mock(
        return_value=AIMessage(
            content=inspect.cleandoc(
                """\
                <patches>
                <patch>
                <code_lines_to_replace>
                file.py:1-1
                </code_lines_to_replace>
                <patched_code>
                ```python
                patched code
                ```
                </patched_code>
                </patch>
                <patches>
                """
            )
        )
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        state.repo_path = temp_dir
        with open(os.path.join(temp_dir, "file.py"), "w", encoding="utf-8") as f:
            f.write("original code\n")

        result = system_guided_patcher(state)
        assert result["patch_action"] == PatchAction.EVALUATE
        assert (
            result["diff"]
            == """\
--- a/file.py
+++ b/file.py
@@ -1 +1 @@
-original code
+patched code
"""
        )
        assert len(result["messages"]) == 5
        assert isinstance(result["messages"][-2], HumanMessage)
        assert isinstance(result["messages"][-1], AIMessage)


def test_patch_with_retry_patch(
    system_guided_patcher: SystemGuidedPatcher, state: PatchState
) -> None:
    system_guided_patcher.max_n_retries = 2
    state.patch_action = PatchAction.RETRIEVE
    state.messages = [
        SystemMessage(content="test content"),
        HumanMessage(content="test"),
        AIMessage(content="test"),
    ]
    state.retrieved = None
    system_guided_patcher.llm.invoke = Mock(
        side_effect=[
            AIMessage(
                content=inspect.cleandoc(
                    """\
                    <patches>
                    <patch>
                    <code_lines_to_replace>
                    file.py:1-1
                    </code_lines_to_replace>
                    <patched_code>
                    ```python
                    ```
                    </patched_code>
                    </patch>
                    </patches>
                    """
                )
            ),
            AIMessage(
                content=inspect.cleandoc(
                    """\
                    <patches>
                    <patch>
                    <code_lines_to_replace>
                    file.py:1-1
                    </code_lines_to_replace>
                    <patched_code>
                    ```python
                    patched code
                    ```
                    </patched_code>
                    </patch>
                    </patches>
                    """
                )
            ),
        ]
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        state.repo_path = temp_dir
        with open(os.path.join(temp_dir, "file.py"), "w", encoding="utf-8") as f:
            f.write("original code\n")
        result = system_guided_patcher(state)
        assert result["patch_action"] == PatchAction.EVALUATE
        assert (
            result["diff"]
            == """\
--- a/file.py
+++ b/file.py
@@ -1 +1 @@
-original code
+patched code
"""
        )
        assert len(result["messages"]) == 7
        assert isinstance(result["messages"][-2], HumanMessage)
        assert isinstance(result["messages"][-1], AIMessage)


def test_patch_with_retry_next_step(
    system_guided_patcher: SystemGuidedPatcher, state: PatchState
) -> None:
    system_guided_patcher.max_n_retries = 0  # minimum next step retry is 1
    state.patch_action = PatchAction.RETRIEVE
    state.messages = [
        SystemMessage(content="test content"),
        HumanMessage(content="test"),
        AIMessage(content="test"),
    ]
    state.retrieved = None
    system_guided_patcher.llm.invoke = Mock(
        return_value=AIMessage(
            content=inspect.cleandoc(
                """\
                <patches>
                <patch>
                <code_lines_to_replace>
                file.py:1-1
                </code_lines_to_replace>
                <patched_code>
                ```python
                patched code
                ```
                </patched_code>
                </patch>
                </patches>
                """
            )
        )
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        state.repo_path = temp_dir
        with open(os.path.join(temp_dir, "file.py"), "w", encoding="utf-8") as f:
            f.write("original code\n")
        result = system_guided_patcher(state)
        assert result["patch_action"] == PatchAction.EVALUATE
        assert (
            result["diff"]
            == """\
--- a/file.py
+++ b/file.py
@@ -1 +1 @@
-original code
+patched code
"""
        )
        assert len(result["messages"]) == 5
        assert isinstance(result["messages"][-2], HumanMessage)
        assert isinstance(result["messages"][-1], AIMessage)
