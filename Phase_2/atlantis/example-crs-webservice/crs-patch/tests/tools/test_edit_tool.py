import logging
import pytest
import tempfile
from pathlib import Path

from crete.framework.coder.services.claude_copy.tools import (
    EditTool,
)

from langchain_core.tools import ToolException


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


def test_edit_tool(temp_dir: Path):
    src_dir = Path(temp_dir) / "src"
    src_dir.mkdir()

    (src_dir / "test").write_text("test1\ntest2\ntest3\n")

    tool = EditTool(logging.getLogger("unittest"), src_dir)

    with pytest.raises(ToolException):
        tool.run(
            {
                "file_path": (src_dir.parent).as_posix(),
                "old_string": "",
                "new_string": "",
            }
        )

    with pytest.raises(ToolException):
        tool.run(
            {
                "file_path": (src_dir / "non_exist").as_posix(),
                "old_string": "",
                "new_string": "",
            }
        )

    with pytest.raises(ToolException):
        tool.run(
            {
                "file_path": (src_dir).as_posix(),
                "old_string": "",
                "new_string": "",
            }
        )

    assert (src_dir / "test").read_text() == "test1\ntest2\ntest3\n"

    with pytest.raises(ToolException):
        tool.run(
            {
                "file_path": (src_dir / "test").as_posix(),
                "old_string": "abc",
                "new_string": "efg",
            }
        )

    assert (src_dir / "test").read_text() == "test1\ntest2\ntest3\n"

    with pytest.raises(ToolException):
        tool.run(
            {
                "file_path": (src_dir / "test").as_posix(),
                "old_string": "test",
                "new_string": "new_test",
            }
        )

    assert (src_dir / "test").read_text() == "test1\ntest2\ntest3\n"

    tool_result = tool.run(
        {
            "file_path": (src_dir / "test").as_posix(),
            "old_string": "test2",
            "new_string": "new_test2",
        }
    )

    assert (
        tool_result
        == f"The file {(src_dir / 'test').as_posix()} has been edited successfully"
    )
    assert (src_dir / "test").read_text() == "test1\nnew_test2\ntest3\n"
