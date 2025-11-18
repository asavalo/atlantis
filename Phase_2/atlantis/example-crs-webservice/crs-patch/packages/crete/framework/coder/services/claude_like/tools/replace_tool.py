from typing import Optional
from pathlib import Path

from pydantic import BaseModel, Field

from langchain_core.callbacks import (
    CallbackManagerForToolRun,
)

from langchain_core.tools import BaseTool, ToolException
from langchain_core.tools.base import ArgsSchema

from logging import Logger


class ReplaceInput(BaseModel):
    file_path: str = Field(description="The file path to write (absolute path)")
    content: str = Field(description="The content to write")


class ReplaceTool(BaseTool):
    name: str = "Replace"
    description: str = """Writes a file at the given file path. If the file exists, it overwrites it. Use only after fully understanding the entire file contents and directory structure.

When to use this tool
- Used to change the entire contents of a file or create a new file.
- NEVER use it to modify just a part of the file.
"""
    args_schema: Optional[ArgsSchema] = ReplaceInput
    return_direct: bool = False

    def __init__(self, logger: Logger, source_directory: Path):
        super().__init__()
        self._logger = logger
        self._source_directory = source_directory

    def _run(
        self,
        file_path: str,
        content: str,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        self._logger.info("[Tool Call] ReplaceTool")
        self._logger.info(f"file_path: {file_path}")
        self._logger.info(f"content: {content}")

        if not Path(file_path).is_relative_to(self._source_directory):
            raise ToolException(
                f"The file {file_path} is outside the working directory"
            )

        if Path(file_path).is_dir():
            raise ToolException(f"The file {file_path} is a directory")

        try:
            Path(file_path).write_text(content)
        except Exception as e:
            raise ToolException(f"Error occured while writing file : {e}")

        return f"The file {file_path} has been updated"
