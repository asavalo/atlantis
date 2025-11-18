import logging
import pytest
import tempfile
from pathlib import Path

from crete.framework.coder.services.claude_copy.tools import (
    GlobTool,
)
from crete.framework.coder.services.claude_copy.tools.glob_tool import MAX_GLOB_RESULT

from langchain_core.tools import ToolException


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


def test_glob_tool(temp_dir: Path):
    src_dir = Path(temp_dir) / "src"
    src_dir.mkdir()

    for i in range(200):
        (src_dir / f"test{i + 1}").write_text("")

    tool = GlobTool(logging.getLogger("unittest"), src_dir)

    with pytest.raises(ToolException):
        tool.run({"pattern": "*", "path": (src_dir.parent).as_posix()})

    with pytest.raises(ToolException):
        tool.run({"pattern": "*", "path": (src_dir / "non_exist").as_posix()})

    with pytest.raises(ToolException):
        tool.run({"pattern": "*", "path": (src_dir / "test1").as_posix()})

    tool_result = tool.run({"pattern": "nosuchpattern*", "path": (src_dir).as_posix()})
    assert isinstance(tool_result, str)
    assert tool_result == "No matching files found"

    tool_result = tool.run({"pattern": "test10*", "path": (src_dir).as_posix()})
    assert isinstance(tool_result, str)

    sorted_result = "\n".join(list(sorted(tool_result.split("\n"))))
    expected_result = "\n".join(
        [(src_dir / "test10").as_posix()]
        + [(src_dir / f"test10{i}").as_posix() for i in range(0, 10)]
    )

    assert sorted_result == expected_result

    tool_result = tool.run({"pattern": "*", "path": (src_dir).as_posix()})
    assert isinstance(tool_result, str)
    assert tool_result.endswith(f"(truncated, maximum {MAX_GLOB_RESULT} results)")
