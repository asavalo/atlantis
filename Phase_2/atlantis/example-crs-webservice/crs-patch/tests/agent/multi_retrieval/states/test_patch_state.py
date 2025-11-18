import os
import tempfile
from unittest.mock import patch

import pytest
from crete.framework.agent.services.multi_retrieval.states.patch_state import (
    CodeDiff,
    CodeSnippet,
    PatchAction,
    PatchState,
    PatchStatus,
    format_patches_to_str,
)
from langchain_core.messages import HumanMessage


@pytest.fixture
def code_diff() -> CodeDiff:
    return CodeDiff()


def test_patch_state_initialization():
    patch_state = PatchState()
    assert patch_state.patch_action == PatchAction.EVALUATE
    assert patch_state.patch_status == PatchStatus.INITIALIZED
    assert not patch_state.messages
    assert patch_state.repo_path == ""
    assert patch_state.diff == ""
    assert patch_state.n_evals == 0
    assert patch_state.issue is None
    assert patch_state.retrieved is None


def test_patch_state_custom_initialization():
    messages = [HumanMessage(content="Test message")]
    patch_state = PatchState(
        patch_action=PatchAction.PATCH,
        patch_status=PatchStatus.COMPILABLE,
        messages=messages,  # type: ignore
        repo_path="/path/to/repo",
        diff="diff content",
        n_evals=5,
        issue="Test issue",
        retrieved="Retrieved content",
    )
    assert patch_state.patch_action == PatchAction.PATCH
    assert patch_state.patch_status == PatchStatus.COMPILABLE
    assert patch_state.messages == messages
    assert patch_state.repo_path == "/path/to/repo"
    assert patch_state.diff == "diff content"
    assert patch_state.n_evals == 5
    assert patch_state.issue == "Test issue"
    assert patch_state.retrieved == "Retrieved content"


def test_add_patches_content_empty(code_diff: CodeDiff) -> None:
    patch_code = CodeSnippet(
        repo_path="temp_dir",
        file_path="file.py",
        line_start=1,
        line_end=2,
        content="",
    )
    code_diff.add_patches([patch_code])
    assert len(code_diff.failed_patches) == 1
    assert patch_code in code_diff.failed_patches
    assert len(code_diff.diff_by_file) == 0


def test_add_patches_file_not_exists(code_diff: CodeDiff) -> None:
    patch_code = CodeSnippet(
        repo_path="temp_dir",
        file_path="file.py",
        line_start=1,
        line_end=2,
        content="patched code",
    )
    with patch("os.path.exists", return_value=False):
        code_diff.add_patches([patch_code])
        assert len(code_diff.failed_patches) == 1
        assert patch_code in code_diff.failed_patches
        assert len(code_diff.diff_by_file) == 0
        code_diff.clear()

    with patch("os.path.isfile", return_value=False):
        code_diff.add_patches([patch_code])
        assert len(code_diff.failed_patches) == 1
        assert patch_code in code_diff.failed_patches
        assert len(code_diff.diff_by_file) == 0


def test_add_patches_invalid_line_range(code_diff: CodeDiff) -> None:
    patch_code = CodeSnippet(
        repo_path="temp_dir",
        file_path="file.py",
        line_start=0,
        line_end=2,
        content="patched code",
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        patch_code.repo_path = temp_dir
        temp_file_path = os.path.join(temp_dir, patch_code.file_path)
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write("line 1\nline 2\nline 3\n")
        code_diff.add_patches([patch_code])
        assert len(code_diff.failed_patches) == 1
        assert patch_code in code_diff.failed_patches
        assert len(code_diff.diff_by_file) == 0
        code_diff.clear()

        patch_code.line_start = 1
        patch_code.line_end = 4
        code_diff.add_patches([patch_code])
        assert len(code_diff.failed_patches) == 1
        assert patch_code in code_diff.failed_patches
        assert len(code_diff.diff_by_file) == 0


def test_add_patches_full_file(code_diff: CodeDiff) -> None:
    patch_code = CodeSnippet(
        repo_path="temp_dir",
        file_path="file.py",
        line_start=1,
        line_end=3,
        content="patched code",
    )
    expected_diff_no_newline_end = """\
--- a/file.py
+++ b/file.py
@@ -1,3 +1,3 @@
-line 1
-line 2
-line 3
\\ No newline at end of file
+patched code line 1
+patched code line 2
+patched code line 3
"""
    with tempfile.TemporaryDirectory() as temp_dir:
        patch_code.repo_path = temp_dir
        temp_file_path = os.path.join(temp_dir, patch_code.file_path)
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write("line 1\nline 2\nline 3")

        patch_code.content = (
            "patched code line 1\npatched code line 2\npatched code line 3"
        )
        code_diff.add_patches([patch_code])
        assert len(code_diff.diff_by_file) == 1
        assert code_diff.concatenated_diff == expected_diff_no_newline_end
        assert len(code_diff.failed_patches) == 0
        code_diff.clear()

        patch_code.content = (
            "patched code line 1\npatched code line 2\npatched code line 3\n"
        )
        code_diff.add_patches([patch_code])
        assert len(code_diff.diff_by_file) == 1
        assert code_diff.concatenated_diff == expected_diff_no_newline_end
        assert len(code_diff.failed_patches) == 0
        code_diff.clear()

    expected_diff_newline_end = """\
--- a/file.py
+++ b/file.py
@@ -1,3 +1,3 @@
-line 1
-line 2
-line 3
+patched code line 1
+patched code line 2
+patched code line 3
"""
    with tempfile.TemporaryDirectory() as temp_dir:
        patch_code.repo_path = temp_dir
        temp_file_path = os.path.join(temp_dir, patch_code.file_path)
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write("line 1\nline 2\nline 3\n")

        patch_code.content = (
            "patched code line 1\npatched code line 2\npatched code line 3"
        )
        code_diff.add_patches([patch_code])
        assert len(code_diff.diff_by_file) == 1
        assert code_diff.concatenated_diff == expected_diff_newline_end
        assert len(code_diff.failed_patches) == 0
        code_diff.clear()

        patch_code.content = (
            "patched code line 1\npatched code line 2\npatched code line 3\n"
        )
        code_diff.add_patches([patch_code])
        assert len(code_diff.diff_by_file) == 1
        assert code_diff.concatenated_diff == expected_diff_newline_end
        assert len(code_diff.failed_patches) == 0
        code_diff.clear()


def test_add_patches_single_patched(code_diff: CodeDiff) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        patch_code = CodeSnippet(
            repo_path=temp_dir,
            file_path="file.py",
            line_start=1,
            line_end=2,
            content="patched code line 1\npatched code line 2\n",
        )

        temp_file_path = os.path.join(temp_dir, patch_code.file_path)
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write("line 1\nline 2\nline 3\n")

        code_diff.add_patches([patch_code])
        assert len(code_diff.diff_by_file) == 1
        assert (
            code_diff.concatenated_diff
            == """\
--- a/file.py
+++ b/file.py
@@ -1,3 +1,3 @@
-line 1
-line 2
+patched code line 1
+patched code line 2
 line 3
"""
        )
        assert len(code_diff.failed_patches) == 0
        code_diff.clear()

        patch_code.line_start = 2
        patch_code.line_end = 3
        patch_code.content = "patched code line 2\npatched code line 3\n"
        code_diff.add_patches([patch_code])
        assert len(code_diff.diff_by_file) == 1
        assert (
            code_diff.concatenated_diff
            == """\
--- a/file.py
+++ b/file.py
@@ -1,3 +1,3 @@
 line 1
-line 2
-line 3
+patched code line 2
+patched code line 3
"""
        )
        assert len(code_diff.failed_patches) == 0
        code_diff.clear()

        patch_code.line_start = 2
        patch_code.line_end = 2
        patch_code.content = "patched code line 2\n"
        code_diff.add_patches([patch_code])
        assert len(code_diff.diff_by_file) == 1
        assert (
            code_diff.concatenated_diff
            == """\
--- a/file.py
+++ b/file.py
@@ -1,3 +1,3 @@
 line 1
-line 2
+patched code line 2
 line 3
"""
        )
        assert len(code_diff.failed_patches) == 0
        code_diff.clear()

        patch_code.line_start = 2
        patch_code.line_end = 2
        patch_code.content = "patched code line 2"
        code_diff.add_patches([patch_code])
        assert len(code_diff.diff_by_file) == 1
        assert (
            code_diff.concatenated_diff
            == """\
--- a/file.py
+++ b/file.py
@@ -1,3 +1,3 @@
 line 1
-line 2
+patched code line 2
 line 3
"""
        )
        assert len(code_diff.failed_patches) == 0
        code_diff.clear()

        # Test with line number in the the patch content
        patch_code.line_start = 2
        patch_code.line_end = 2
        patch_code.content = "2:patched code line 2"
        code_diff.add_patches([patch_code])
        assert len(code_diff.diff_by_file) == 1
        assert (
            code_diff.concatenated_diff
            == """\
--- a/file.py
+++ b/file.py
@@ -1,3 +1,3 @@
 line 1
-line 2
+patched code line 2
 line 3
"""
        )
        assert len(code_diff.failed_patches) == 0
        code_diff.clear()


def test_add_patches_single_patched_no_newline_end(code_diff: CodeDiff) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        patch_code = CodeSnippet(
            repo_path=temp_dir,
            file_path="file.py",
            line_start=1,
            line_end=2,
            content="patched code line 1\npatched code line 2\n",
        )

        temp_file_path = os.path.join(temp_dir, patch_code.file_path)
        # Test no newline at the end of the file
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write("line 1\nline 2\nline 3")

        patch_code.line_start = 2
        patch_code.line_end = 2
        patch_code.content = "patched code line 2"
        code_diff.add_patches([patch_code])
        assert len(code_diff.diff_by_file) == 1
        assert (
            code_diff.concatenated_diff
            == """\
--- a/file.py
+++ b/file.py
@@ -1,3 +1,3 @@
 line 1
-line 2
+patched code line 2
-line 3
\\ No newline at end of file
+line 3
"""
        )
        assert len(code_diff.failed_patches) == 0
        code_diff.clear()

        patch_code.line_start = 2
        patch_code.line_end = 3
        patch_code.content = "patched code line 2\npatched code line 3\n"
        code_diff.add_patches([patch_code])
        assert len(code_diff.diff_by_file) == 1
        assert (
            code_diff.concatenated_diff
            == """\
--- a/file.py
+++ b/file.py
@@ -1,3 +1,3 @@
 line 1
-line 2
-line 3
\\ No newline at end of file
+patched code line 2
+patched code line 3
"""
        )
        assert len(code_diff.failed_patches) == 0
        code_diff.clear()


def test_add_patches_fuzz_file_filter(code_diff: CodeDiff) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        patch_code = CodeSnippet(
            repo_path=temp_dir,
            file_path="fuzz_file.c",
            line_start=1,
            line_end=2,
            content="patched code line 1\npatched code line 2\n",
        )

        temp_file_path = os.path.join(temp_dir, patch_code.file_path)
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write("line 1\nline 2\nline 3\n")

        code_diff.add_patches([patch_code], filter_out_fuzz_files=False)
        assert len(code_diff.diff_by_file) == 1
        assert (
            code_diff.concatenated_diff
            == """\
--- a/fuzz_file.c
+++ b/fuzz_file.c
@@ -1,3 +1,3 @@
-line 1
-line 2
+patched code line 1
+patched code line 2
 line 3
"""
        )
        assert len(code_diff.failed_patches) == 0
        code_diff.clear()

        patch_code.line_start = 2
        code_diff.add_patches([patch_code], filter_out_fuzz_files=True)
        assert len(code_diff.diff_by_file) == 0
        assert code_diff.concatenated_diff == ""
        assert len(code_diff.failed_patches) == 1


def test_add_patches_multi_patched(code_diff: CodeDiff) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        patch_code1 = CodeSnippet(
            repo_path=temp_dir,
            file_path="file1.py",
            line_start=3,
            line_end=3,
            content="patched code line 1-3\n",
        )
        patch_code2 = CodeSnippet(
            repo_path=temp_dir,
            file_path="file2.py",
            line_start=3,
            line_end=3,
            content="patched code line 2-3\n",
        )
        patch_code3 = CodeSnippet(
            repo_path=temp_dir,
            file_path="file2.py",
            line_start=1,
            line_end=2,
            content="patched code line 2-1\npatched code line 2-2\n",
        )

        temp_file_path1 = os.path.join(temp_dir, patch_code1.file_path)
        with open(temp_file_path1, "w", encoding="utf-8") as f:
            f.write("line 1-1\nline 1-2\nline 1-3\n")
        temp_file_path2 = os.path.join(temp_dir, patch_code2.file_path)
        with open(temp_file_path2, "w", encoding="utf-8") as f:
            f.write("line 2-1\nline 2-2\nline 2-3\n")

        code_diff.add_patches([patch_code1, patch_code2, patch_code3])
        assert len(code_diff.diff_by_file) == 2
        assert (
            code_diff.concatenated_diff
            == """\
--- a/file1.py
+++ b/file1.py
@@ -1,3 +1,3 @@
 line 1-1
 line 1-2
-line 1-3
+patched code line 1-3

--- a/file2.py
+++ b/file2.py
@@ -1,3 +1,3 @@
-line 2-1
-line 2-2
-line 2-3
+patched code line 2-1
+patched code line 2-2
+patched code line 2-3
"""
        )
        assert len(code_diff.failed_patches) == 0
        code_diff.clear()

        # Test with crlf in file2.py
        with open(temp_file_path2, "w", encoding="utf-8") as f:
            f.write("line 2-1\r\nline 2-2\r\nline 2-3\r\n")

        code_diff.add_patches([patch_code1, patch_code2, patch_code3])
        assert len(code_diff.diff_by_file) == 2
        assert (
            code_diff.concatenated_diff
            == """\
--- a/file1.py
+++ b/file1.py
@@ -1,3 +1,3 @@
 line 1-1
 line 1-2
-line 1-3
+patched code line 1-3

--- a/file2.py
+++ b/file2.py
@@ -1,3 +1,3 @@
-line 2-1\r
-line 2-2\r
-line 2-3\r
+patched code line 2-1\r
+patched code line 2-2\r
+patched code line 2-3\r
"""
        )


def test_format_patches_to_str() -> None:
    patches = [
        CodeSnippet(
            file_path="file1.py",
            line_start=1,
            line_end=1,
            content="patched code 1\n",
        ),
        CodeSnippet(
            file_path="file2.py",
            line_start=2,
            line_end=3,
            content="patched code 2-2\npatched code 2-3\n",
        ),
    ]
    with tempfile.TemporaryDirectory() as temp_dir:
        patches[0].repo_path = temp_dir
        patches[1].repo_path = temp_dir
        temp_file_path = os.path.join(temp_dir, patches[0].file_path)
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write("line 1\nline 2\nline 3\n")
        temp_file_path = os.path.join(temp_dir, patches[1].file_path)
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write("line 2-1\nline 2-2\nline 2-3\n")
        patch_str = format_patches_to_str(patches, add_line_numbers=True)
        assert (
            patch_str
            == """\
<patches>
<patch>
<original_code>
```
1:line 1
```
</original_code>
<code_lines_to_replace>
file1.py:1-1
</code_lines_to_replace>
<patched_code>
```
patched code 1
```
</patched_code>
</patch>
<patch>
<original_code>
```
2:line 2-2
3:line 2-3
```
</original_code>
<code_lines_to_replace>
file2.py:2-3
</code_lines_to_replace>
<patched_code>
```
patched code 2-2
patched code 2-3
```
</patched_code>
</patch>
</patches>"""
        )
        patch_str = format_patches_to_str(patches, add_line_numbers=False)
        assert (
            patch_str
            == """\
<patches>
<patch>
<original_code>
```
line 1
```
</original_code>
<code_lines_to_replace>
file1.py:1-1
</code_lines_to_replace>
<patched_code>
```
patched code 1
```
</patched_code>
</patch>
<patch>
<original_code>
```
line 2-2
line 2-3
```
</original_code>
<code_lines_to_replace>
file2.py:2-3
</code_lines_to_replace>
<patched_code>
```
patched code 2-2
patched code 2-3
```
</patched_code>
</patch>
</patches>"""
        )

        patches[0].content = "1:patched code 1\n"
        patches[1].content = "2:patched code 2-2\n3:patched code 2-3\n"
        patch_str = format_patches_to_str(patches, add_line_numbers=True)
        assert (
            patch_str
            == """\
<patches>
<patch>
<original_code>
```
1:line 1
```
</original_code>
<code_lines_to_replace>
file1.py:1-1
</code_lines_to_replace>
<patched_code>
```
patched code 1
```
</patched_code>
</patch>
<patch>
<original_code>
```
2:line 2-2
3:line 2-3
```
</original_code>
<code_lines_to_replace>
file2.py:2-3
</code_lines_to_replace>
<patched_code>
```
patched code 2-2
patched code 2-3
```
</patched_code>
</patch>
</patches>"""
        )
