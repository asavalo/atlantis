import inspect

from crete.framework.agent.services.multi_retrieval.states.patch_state import (
    CodeSnippet,
)
from crete.framework.agent.services.prism.states.analysis_team_state import AnalysisCell


def test_analysis_cell_from_str() -> None:
    cell_content_valid = inspect.cleandoc(
        """\
        <code_range>test_file1.py:1-22</code_range>
        <code_range>test_file2.py:11-32</code_range>
        <analysis>test analysis</analysis>
        """
    )
    cell = AnalysisCell.from_str(cell_content_valid)
    assert cell is not None
    assert len(cell.code_snippets) == 2
    assert cell.code_snippets[0].file_path == "test_file1.py"
    assert cell.code_snippets[0].line_start == 1
    assert cell.code_snippets[0].line_end == 22
    assert cell.code_snippets[1].file_path == "test_file2.py"
    assert cell.code_snippets[1].line_start == 11
    assert cell.code_snippets[1].line_end == 32
    assert cell.analysis == "test analysis"

    cell_content_without_analysis = inspect.cleandoc(
        """\
        <code_range>test_file1.py:1-22</code_range>
        <code_range>test_file2.py:11-32</code_range>
        """
    )
    cell = AnalysisCell.from_str(cell_content_without_analysis)
    assert cell is None

    cell_content_without_code_range = inspect.cleandoc(
        """\
        <analysis>test analysis</analysis>
        """
    )
    cell = AnalysisCell.from_str(cell_content_without_code_range)
    assert cell is None

    cell_content_invalid_line_range = inspect.cleandoc(
        """\
        <code_range>test_file1.py:1</code_range>
        <code_range>test_file2.py:32</code_range>
        <analysis>test analysis</analysis>
        """
    )
    cell = AnalysisCell.from_str(cell_content_invalid_line_range)
    assert cell is None

    cell_content_invalid_line_range2 = inspect.cleandoc(
        """\
        <code_range>test_file1.py</code_range>
        <code_range>test_file2.py</code_range>
        <analysis>test analysis</analysis>
        """
    )
    cell = AnalysisCell.from_str(cell_content_invalid_line_range2)
    assert cell is None


def test_analysis_cell_to_str() -> None:
    cell = AnalysisCell(
        code_snippets=[
            CodeSnippet(file_path="test_file1.py", line_start=1, line_end=2),
            CodeSnippet(file_path="test_file2.py", line_start=15, line_end=16),
        ],
        analysis="test analysis",
    )
    cell_str = cell.to_str(add_analysis=True, add_cell_tags=False)
    assert (
        cell_str
        == """\
<code_range>test_file1.py:1-2</code_range>
<code_range>test_file2.py:15-16</code_range>
<analysis>
test analysis
</analysis>"""
    )

    cell.code_snippets[0].content = "def test():\n    pass\n"
    cell.code_snippets[1].content = "def test2():\n    pass"

    cell_str = cell.to_str(add_analysis=True, add_cell_tags=False)
    assert (
        cell_str
        == """\
<code>
test_file1.py:1-2
```
def test():
    pass
```
</code>
<code>
test_file2.py:15-16
```
def test2():
    pass
```
</code>
<analysis>
test analysis
</analysis>"""
    )

    cell_str = cell.to_str(add_analysis=False, add_cell_tags=False)
    assert (
        cell_str
        == """\
<code>
test_file1.py:1-2
```
def test():
    pass
```
</code>
<code>
test_file2.py:15-16
```
def test2():
    pass
```
</code>"""
    )
    cell_str = cell.to_str(add_analysis=True, add_cell_tags=True)
    assert (
        cell_str
        == """\
<cell>
<code>
test_file1.py:1-2
```
def test():
    pass
```
</code>
<code>
test_file2.py:15-16
```
def test2():
    pass
```
</code>
<analysis>
test analysis
</analysis>
</cell>"""
    )
