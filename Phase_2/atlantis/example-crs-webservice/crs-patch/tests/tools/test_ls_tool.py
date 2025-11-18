import logging
import pytest
import tempfile
from pathlib import Path

from crete.framework.coder.services.claude_copy.tools import (
    LSTool,
)

from langchain_core.tools import ToolException


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


def test_ls_tool(temp_dir: Path):
    src_dir = Path(temp_dir) / "src"
    src_dir.mkdir()

    (src_dir / "test1").write_text("test")
    (src_dir / "test2").write_text("test")
    (src_dir / "test3").write_text("test")

    tool = LSTool(logging.getLogger("unittest"), src_dir)

    with pytest.raises(ToolException):
        tool.run({"path": (src_dir.parent).as_posix()})

    with pytest.raises(ToolException):
        tool.run({"path": (src_dir / "non_exist").as_posix()})

    with pytest.raises(ToolException):
        tool.run({"path": (src_dir / "test1").as_posix()})

    tool_result = tool.run({"path": src_dir.as_posix()})

    assert isinstance(tool_result, str)

    assert tool_result.startswith("""- src/
  - test1
  - test2
  - test3""")
