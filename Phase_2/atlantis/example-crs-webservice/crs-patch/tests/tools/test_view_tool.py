import logging
import pytest
import tempfile
from pathlib import Path

from crete.framework.coder.services.claude_copy.tools import (
    ViewTool,
)

from langchain_core.tools import ToolException


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


def test_view_tool(temp_dir: Path):
    src_dir = Path(temp_dir) / "src"
    src_dir.mkdir()

    (src_dir / "test1").write_text(
        "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\np\nq\nr\ns\nt\nu\nv\nw\nx\ny\nz"
    )
    (src_dir / "test2").write_text("a\n" * 4000)
    (src_dir / "test3").write_text("a" * 4000)
    (src_dir / "test4").write_text(("a" * 1000 + "\n") * 1000)

    tool = ViewTool(logging.getLogger("unittest"), src_dir)

    with pytest.raises(ToolException):
        tool.run(
            {
                "file_path": (src_dir.parent).as_posix(),
                "offset": None,
                "limit": None,
            }
        )

    with pytest.raises(ToolException):
        tool.run(
            {
                "file_path": (src_dir / "non_exist").as_posix(),
                "offset": None,
                "limit": None,
            }
        )

    with pytest.raises(ToolException):
        tool.run(
            {
                "file_path": (src_dir).as_posix(),
                "offset": None,
                "limit": None,
            }
        )

    tool_result = tool.run(
        {
            "file_path": (src_dir / "test1").as_posix(),
            "offset": 5,
            "limit": 4,
        }
    )

    assert isinstance(tool_result, str)
    assert (
        tool_result
        == """     5\te
     6\tf
     7\tg
     8\th"""
    )

    tool_result = tool.run(
        {
            "file_path": (src_dir / "test2").as_posix(),
            "offset": None,
            "limit": None,
        }
    )
    assert isinstance(tool_result, str)
    assert tool_result == "\n".join([f"{i + 1: >{6}}\ta" for i in range(0, 1000)])

    tool_result = tool.run(
        {
            "file_path": (src_dir / "test3").as_posix(),
            "offset": None,
            "limit": None,
        }
    )
    assert isinstance(tool_result, str)
    assert tool_result == "     1\t" + "a" * (1000 - 7)

    with pytest.raises(ToolException):
        tool_result = tool.run(
            {
                "file_path": (src_dir / "test4").as_posix(),
                "offset": None,
                "limit": None,
            }
        )
