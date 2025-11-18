import inspect
import os
import tempfile
from unittest.mock import Mock

import pytest
from crete.framework.agent.services.prism.states.patch_team_state import (
    PatchTeamState,
)
from crete.framework.agent.services.prism.teams.patch.patch_generator import (
    PatchGenerator,
)
from langchain_core.messages import AIMessage


@pytest.fixture
def patch_generator() -> PatchGenerator:
    mock_patch_generator = PatchGenerator(llm=Mock())
    mock_patch_generator.llm.invoke = Mock(
        return_value=AIMessage(content="test content")
    )
    return mock_patch_generator


@pytest.fixture
def state() -> PatchTeamState:
    return PatchTeamState()


def test_basic_call(patch_generator: PatchGenerator, state: PatchTeamState) -> None:
    state.analysis_report = ""
    state.evaluation_report = "test evaluation report"
    with pytest.raises(ValueError):
        patch_generator(state)

    state.analysis_report = "test analysis report"
    state.evaluation_report = ""
    with pytest.raises(ValueError):
        patch_generator(state)

    state.analysis_report = "test analysis report"
    state.evaluation_report = "test evaluation report"

    with tempfile.TemporaryDirectory() as temp_dir:
        state.repo_path = temp_dir
        temp_file_path1 = os.path.join(temp_dir, "file1.py")
        with open(temp_file_path1, "w", encoding="utf-8") as f:
            f.write("line 1-1\nline 1-2\nline 1-3\n")
        temp_file_path2 = os.path.join(temp_dir, "file2.py")
        with open(temp_file_path2, "w", encoding="utf-8") as f:
            f.write("line 2-1\nline 2-2\nline 2-3\n")

        patch_content = inspect.cleandoc(
            """\
            <patch>
            <original_code>
            ```python
            line 1-1
            line 1-2
            ```
            </original_code>
            <code_lines_to_replace>
            file1.py:1-2
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            </patch>
            <patch>
            <original_code>
            ```python
            line 2-2
            line 2-3
            ```
            </original_code>
            <code_lines_to_replace>
            file2.py:2-3
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            </patch>
            """
        )
        patch_generator.llm.invoke = Mock(return_value=AIMessage(content=patch_content))
        result = patch_generator(state)
        assert len(result["messages"]) == 3
        assert (
            result["diff"]
            == """\
--- a/file1.py
+++ b/file1.py
@@ -1,3 +1,2 @@
-line 1-1
-line 1-2
+patched code
 line 1-3

--- a/file2.py
+++ b/file2.py
@@ -1,3 +1,2 @@
 line 2-1
-line 2-2
-line 2-3
+patched code
"""
        )

        state.messages = []
        patch_content_with_mistakes_correction = inspect.cleandoc(
            """\
            <patch>
            <original_code>
            ```python
            line 1-1
            line 1-2
            ```
            </original_code>
            <code_lines_to_replace>
            file1.py:2-3
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            </patch>
            <patch>
            <original_code>
            ```python
            line 2-2
            line 2-3
            ```
            </original_code>
            <code_lines_to_replace>
            file2.py:1-2
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            </patch>
            """
        )
        patch_generator.llm.invoke = Mock(
            return_value=AIMessage(content=patch_content_with_mistakes_correction)
        )
        result = patch_generator(state)
        assert len(result["messages"]) == 3
        assert (
            result["diff"]
            == """\
--- a/file1.py
+++ b/file1.py
@@ -1,3 +1,2 @@
-line 1-1
-line 1-2
+patched code
 line 1-3

--- a/file2.py
+++ b/file2.py
@@ -1,3 +1,2 @@
 line 2-1
-line 2-2
-line 2-3
+patched code
"""
        )

        state.messages = []
        patch_content = inspect.cleandoc(
            """\
            <patch>
            <code_lines_to_replace>
            file1.py:1-2
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            </patch>
            <patch>
            <code_lines_to_replace>
            file2.py:2-3
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            </patch>
            """
        )
        patch_generator.llm.invoke = Mock(return_value=AIMessage(content=patch_content))
        result = patch_generator(state)
        assert len(result["messages"]) == 3
        assert (
            result["diff"]
            == """\
--- a/file1.py
+++ b/file1.py
@@ -1,3 +1,2 @@
-line 1-1
-line 1-2
+patched code
 line 1-3

--- a/file2.py
+++ b/file2.py
@@ -1,3 +1,2 @@
 line 2-1
-line 2-2
-line 2-3
+patched code
"""
        )
