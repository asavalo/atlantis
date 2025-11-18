import logging
import pytest
import tempfile
from pathlib import Path

from crete.framework.coder.services.claude_copy.tools import (
    ReplaceTool,
)

from langchain_core.tools import ToolException


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


def test_replace_tool(temp_dir: Path):
    src_dir = Path(temp_dir) / "src"
    src_dir.mkdir()

    (src_dir / "test1").write_text("test")

    tool = ReplaceTool(logging.getLogger("unittest"), src_dir)

    with pytest.raises(ToolException):
        tool.run(
            {
                "file_path": (src_dir.parent).as_posix(),
                "content": "",
            }
        )

    with pytest.raises(ToolException):
        tool.run(
            {
                "file_path": (src_dir).as_posix(),
                "content": "",
            }
        )

    assert (src_dir / "test1").read_text() == "test"
    tool_result = tool.run(
        {
            "file_path": (src_dir / "test1").as_posix(),
            "content": "new test",
        }
    )
    assert tool_result == f"The file {(src_dir / 'test1').as_posix()} has been updated"
    assert (src_dir / "test1").read_text() == "new test"

    assert not (src_dir / "test2").exists()
    tool_result = tool.run(
        {
            "file_path": (src_dir / "test2").as_posix(),
            "content": "hello",
        }
    )
    assert tool_result == f"The file {(src_dir / 'test2').as_posix()} has been updated"
    assert (src_dir / "test2").read_text() == "hello"
