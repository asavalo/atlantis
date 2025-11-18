import inspect
import os
import tempfile

import pytest
from crete.framework.agent.services.multi_retrieval.nodes.patchers.line_range_patch_extractor import (
    LineRangePatchExtractor,
)


@pytest.fixture
def line_range_patch_extractor() -> LineRangePatchExtractor:
    mock_line_range_patch_extractor = LineRangePatchExtractor(n_check_lines=3)
    return mock_line_range_patch_extractor


def test_extract_patch_from_content(
    line_range_patch_extractor: LineRangePatchExtractor,
) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_path = temp_dir
        temp_file_path = os.path.join(temp_dir, "file.py")
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write("line 1-1\nline 1-2\nline 1-3\n")

        single_patch_invalid_line_content = inspect.cleandoc(
            """
            <original_code>
            ```python
            line 1-1
            ```
            </original_code>
            <code_lines_to_replace>
            file.py
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            """
        )
        patch_snippet = line_range_patch_extractor.extract_patch_from_content(
            repo_path, single_patch_invalid_line_content
        )
        assert patch_snippet.repo_path == ""
        assert patch_snippet.file_path == ""
        assert patch_snippet.line_start == 0
        assert patch_snippet.line_end == 0

        single_patch_invalid_line_content = inspect.cleandoc(
            """
            <original_code>
            ```python
            line 1-1
            ```
            </original_code>
            <code_lines_to_replace>
            file.py:line_start-line_end
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            """
        )
        patch_snippet = line_range_patch_extractor.extract_patch_from_content(
            repo_path, single_patch_invalid_line_content
        )
        assert patch_snippet.repo_path == ""
        assert patch_snippet.file_path == ""
        assert patch_snippet.line_start == 0
        assert patch_snippet.line_end == 0

        single_patch_one_line_content = inspect.cleandoc(
            """
            <original_code>
            ```python
            line 1-1
            ```
            </original_code>
            <code_lines_to_replace>
            file.py:1
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            """
        )
        patch_snippet = line_range_patch_extractor.extract_patch_from_content(
            repo_path, single_patch_one_line_content
        )
        assert patch_snippet.repo_path == repo_path
        assert patch_snippet.file_path == "file.py"
        assert patch_snippet.line_start == 1
        assert patch_snippet.line_end == 1
        assert patch_snippet.content == "patched code\n"

        single_patch_content = inspect.cleandoc(
            """
            <original_code>
            ```python
            line 1-1
            line 1-2
            ```
            </original_code>
            <code_lines_to_replace>
            file.py:1-2
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            """
        )
        patch_snippet = line_range_patch_extractor.extract_patch_from_content(
            repo_path, single_patch_content
        )
        assert patch_snippet.repo_path == repo_path
        assert patch_snippet.file_path == "file.py"
        assert patch_snippet.line_start == 1
        assert patch_snippet.line_end == 2
        assert patch_snippet.content == "patched code\n"


def test_adjust_line_range_from_original_code(
    line_range_patch_extractor: LineRangePatchExtractor,
) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_path = temp_dir
        temp_file_path = os.path.join(temp_dir, "file.py")
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write("line 1-1\nline 1-2\nline 1-3\nline 1-4\nline 1-5\n")

        patch_content_exact_line_range = inspect.cleandoc(
            """
            <original_code>
            ```python
            line 1-2
            line 1-3
            ```
            </original_code>
            <code_lines_to_replace>
            file.py:2-3
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            """
        )
        patch_snippet = line_range_patch_extractor.extract_patch_from_content(
            repo_path, patch_content_exact_line_range
        )
        assert patch_snippet.repo_path == repo_path
        assert patch_snippet.file_path == "file.py"
        assert patch_snippet.line_start == 2
        assert patch_snippet.line_end == 3
        assert patch_snippet.content == "patched code\n"

        patch_content_exact_numbered_line_range = inspect.cleandoc(
            """
            <original_code>
            ```python
            2:line 1-2
            3:line 1-3
            ```
            </original_code>
            <code_lines_to_replace>
            file.py:2-3
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            """
        )
        patch_snippet = line_range_patch_extractor.extract_patch_from_content(
            repo_path, patch_content_exact_numbered_line_range
        )
        assert patch_snippet.repo_path == repo_path
        assert patch_snippet.file_path == "file.py"
        assert patch_snippet.line_start == 2
        assert patch_snippet.line_end == 3
        assert patch_snippet.content == "patched code\n"

        patch_content_adjustable_line_range = inspect.cleandoc(
            """
            <original_code>
            ```python
            line 1-2
            line 1-3
            ```
            </original_code>
            <code_lines_to_replace>
            file.py:1-2
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            """
        )
        patch_snippet = line_range_patch_extractor.extract_patch_from_content(
            repo_path, patch_content_adjustable_line_range
        )
        assert patch_snippet.repo_path == repo_path
        assert patch_snippet.file_path == "file.py"
        assert patch_snippet.line_start == 2
        assert patch_snippet.line_end == 3
        assert patch_snippet.content == "patched code\n"

        patch_content_adjustable_line_range = inspect.cleandoc(
            """
            <original_code>
            ```python
            line 1-2
            line 1-3
            ```
            </original_code>
            <code_lines_to_replace>
            file.py:3-4
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            """
        )
        patch_snippet = line_range_patch_extractor.extract_patch_from_content(
            repo_path, patch_content_adjustable_line_range
        )
        assert patch_snippet.repo_path == repo_path
        assert patch_snippet.file_path == "file.py"
        assert patch_snippet.line_start == 2
        assert patch_snippet.line_end == 3
        assert patch_snippet.content == "patched code\n"

        patch_content_single_line_range = inspect.cleandoc(
            """
            <original_code>
            ```python
            line 1-2
            ```
            </original_code>
            <code_lines_to_replace>
            file.py:2-3
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            """
        )
        patch_snippet = line_range_patch_extractor.extract_patch_from_content(
            repo_path, patch_content_single_line_range
        )
        assert patch_snippet.repo_path == repo_path
        assert patch_snippet.file_path == "file.py"
        assert patch_snippet.line_start == 2
        assert patch_snippet.line_end == 2
        assert patch_snippet.content == "patched code\n"

        patch_content_adjustable_line_range = inspect.cleandoc(
            """
            <original_code>
            ```python
            line 1-1
            line 1-2
            ```
            </original_code>
            <code_lines_to_replace>
            file.py:4-5
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            """
        )
        patch_snippet = line_range_patch_extractor.extract_patch_from_content(
            repo_path, patch_content_adjustable_line_range
        )
        assert patch_snippet.repo_path == repo_path
        assert patch_snippet.file_path == "file.py"
        assert patch_snippet.line_start == 1
        assert patch_snippet.line_end == 2
        assert patch_snippet.content == "patched code\n"

        patch_content_adjustable_line_range = inspect.cleandoc(
            """
            <original_code>
            ```python
            line 1-2
            line 1-3
            ```
            </original_code>
            <code_lines_to_replace>
            file.py:3-4
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            """
        )
        patch_snippet = line_range_patch_extractor.extract_patch_from_content(
            repo_path, patch_content_adjustable_line_range
        )
        assert patch_snippet.repo_path == repo_path
        assert patch_snippet.file_path == "file.py"
        assert patch_snippet.line_start == 2
        assert patch_snippet.line_end == 3
        assert patch_snippet.content == "patched code\n"

        patch_content_non_adjustable_line_range = inspect.cleandoc(
            """
            <original_code>
            ```python
            line 1-1
            ```
            </original_code>
            <code_lines_to_replace>
            file.py:5-5
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            """
        )
        patch_snippet = line_range_patch_extractor.extract_patch_from_content(
            repo_path, patch_content_non_adjustable_line_range
        )
        assert patch_snippet.repo_path == repo_path
        assert patch_snippet.file_path == "file.py"
        assert patch_snippet.line_start == 5
        assert patch_snippet.line_end == 5
        assert patch_snippet.content == "patched code\n"

        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write("line\n  line\n    line\n      line")
        patch_content_no_strip_adjustable_line_range = inspect.cleandoc(
            """
            <original_code>
            ```python
              line
                line
            ```
            </original_code>
            <code_lines_to_replace>
            file.py:1-4
            </code_lines_to_replace>
            <patched_code>
            ```python
            patched code
            ```
            </patched_code>
            """
        )
        patch_snippet = line_range_patch_extractor.extract_patch_from_content(
            repo_path, patch_content_no_strip_adjustable_line_range
        )
        assert patch_snippet.repo_path == repo_path
        assert patch_snippet.file_path == "file.py"
        assert patch_snippet.line_start == 2
        assert patch_snippet.line_end == 3
        assert patch_snippet.content == "patched code\n"
