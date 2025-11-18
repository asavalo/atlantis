import inspect
import os
import tempfile
from typing import Any
from unittest.mock import Mock

import pytest
from crete.framework.agent.services.multi_retrieval.nodes.patchers.base_patcher import (
    BasePatcher,
)
from crete.framework.agent.services.multi_retrieval.states.patch_state import (
    CodeDiff,
    CodeSnippet,
    PatchState,
)
from langchain_core.messages import AIMessage, HumanMessage


@pytest.fixture
def base_patcher() -> BasePatcher:
    class TestBasePatcher(BasePatcher):
        def __call__(self, state: Any) -> dict[str, Any]:
            raise NotImplementedError

    mock_base_patcher = TestBasePatcher(llm=Mock())
    mock_base_patcher.llm.invoke = Mock(return_value=AIMessage(content="test content"))
    return mock_base_patcher


def test_extract_and_add_patches(
    base_patcher: BasePatcher,
) -> None:
    code_diff = CodeDiff()
    repo_path = "/path/to/repo"
    state = PatchState(messages=[HumanMessage("no patch content")])
    base_patcher._extract_and_add_patches(  # type: ignore
        state, code_diff, repo_path
    )
    assert code_diff.concatenated_diff == ""
    code_diff.clear()

    with tempfile.TemporaryDirectory() as temp_dir:
        repo_path = temp_dir
        temp_file_path1 = os.path.join(temp_dir, "file1.py")
        with open(temp_file_path1, "w", encoding="utf-8") as f:
            f.write("line 1-1\nline 1-2\nline 1-3\n")
        temp_file_path2 = os.path.join(temp_dir, "file2.py")
        with open(temp_file_path2, "w", encoding="utf-8") as f:
            f.write("line 2-1\nline 2-2\nline 2-3\n")

        state.messages[-1].content = inspect.cleandoc(
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
        base_patcher._extract_and_add_patches(  # type: ignore
            state, code_diff, repo_path
        )
        assert (
            code_diff.concatenated_diff
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


def test_format_failed_patches(base_patcher: BasePatcher) -> None:
    failed_patches = [
        CodeSnippet(
            repo_path="temp_dir",
            file_path="file1.py",
            line_start=1,
            line_end=1,
            content="failed 1",
        ),
        CodeSnippet(
            repo_path="temp_dir",
            file_path="file2.py",
            line_start=1,
            line_end=1,
            content="failed 2",
        ),
    ]
    formatted = base_patcher._format_failed_patches(failed_patches)  # type: ignore
    assert formatted == "file1.py:1-1\nfailed 1\n\nfile2.py:1-1\nfailed 2"
