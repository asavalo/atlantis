import logging
import pytest
import tempfile
from pathlib import Path

from crete.framework.coder.services.claude_copy.tools import (
    GrepTool,
)
from crete.framework.coder.services.claude_copy.tools.grep_tool import MAX_GREP_RESULT

from langchain_core.tools import ToolException


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


def test_grep_tool(temp_dir: Path):
    src_dir = Path(temp_dir) / "src"
    src_dir.mkdir()

    for i in range(100):
        (src_dir / f"test{i + 1}.c").write_text(f"source file {i + 1}")
    for i in range(100):
        (src_dir / f"test{i + 1}.h").write_text(f"header file {i + 1}")

    tool = GrepTool(logging.getLogger("unittest"), src_dir)

    with pytest.raises(ToolException):
        tool.run({"pattern": "*", "path": (src_dir.parent).as_posix(), "include": None})

    with pytest.raises(ToolException):
        tool.run(
            {
                "pattern": "*",
                "path": (src_dir / "non_exist").as_posix(),
                "include": None,
            }
        )

    with pytest.raises(ToolException):
        tool.run(
            {
                "pattern": "*",
                "path": (src_dir / "test1").as_posix(),
                "include": None,
            }
        )

    tool_result = tool.run(
        {
            "pattern": "nosuchpattern",
            "path": (src_dir).as_posix(),
            "include": None,
        }
    )
    assert isinstance(tool_result, str)
    assert tool_result == "No matching files found"

    tool_result = tool.run(
        {
            "pattern": "source file 100",
            "path": (src_dir).as_posix(),
            "include": None,
        }
    )

    assert isinstance(tool_result, str)
    assert tool_result.startswith("1 matching file found\n")

    tool_result = tool.run(
        {
            "pattern": "file 1",
            "path": (src_dir).as_posix(),
            "include": None,
        }
    )

    assert isinstance(tool_result, str)
    assert tool_result.startswith("24 matching files found\n")

    tool_result = tool.run(
        {
            "pattern": "file 1",
            "path": (src_dir).as_posix(),
            "include": "*.c",
        }
    )

    assert isinstance(tool_result, str)
    assert tool_result.startswith("12 matching files found\n")

    tool_result = tool.run(
        {
            "pattern": "file",
            "path": (src_dir).as_posix(),
            "include": None,
        }
    )

    assert isinstance(tool_result, str)
    assert tool_result.startswith("200 matching files found\n")
    assert tool_result.endswith(f"(truncated, maximum {MAX_GREP_RESULT} results)")

    tool_result = tool.run(
        {
            "pattern": "(source|header) file",
            "path": (src_dir).as_posix(),
            "include": None,
        }
    )

    assert isinstance(tool_result, str)
    print(tool_result)
    assert tool_result.startswith("200 matching files found\n")
    assert tool_result.endswith(f"(truncated, maximum {MAX_GREP_RESULT} results)")
