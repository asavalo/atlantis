from logging import Logger
from pathlib import Path
from typing import Optional

from langchain_core.callbacks import (
    CallbackManagerForToolRun,
)
from langchain_core.tools import BaseTool, ToolException
from langchain_core.tools.base import ArgsSchema
from pydantic import BaseModel, Field


class EditInput(BaseModel):
    file_path: str = Field(description="The file path to modify (absolute path)")
    old_string: str = Field(description="The string to replace")
    new_string: str = Field(description="The new string to replace the old_string")


class EditTool(BaseTool):
    name: str = "Edit"
    description: str = """Edit the file. Replaces occurrences of old_string with new_string in the contents of the file at the given path.

When to use this tool
- Used to modify a part of a file.

IMPORTANT: Usage Guide
- old_string must be unique throughout the entire file and exactly match the target to be changed. Include at least 3-5 lines before and after the target string, without omitting spaces or indentation, to ensure accuracy.
- This tool changes only one string at a time; use it multiple times for multiple changes, ensuring old_string is unique in each call.
- Use ViewTool or GrepTool to fully understand the file's contents and context before using this tool.
- Ensure the modified code functions correctly and is not left in a broken state (e.g., syntax errors or unmatched brackets).

Note:
- Before modifying a file, verify that the file path is correct and use the View tool to understand the file's contents and context.
- Edit the function by providing the absolute file path, old string, and new string.
- old_string must be unique within the function, and must match the function contents exactly, including all whitespace and indentation.
- new_string is the edited text to replace the old_string.
"""
    args_schema: Optional[ArgsSchema] = EditInput
    return_direct: bool = False

    def __init__(self, logger: Logger, source_directory: Path):
        super().__init__()
        self._logger = logger
        self._source_directory = source_directory

    def _run(
        self,
        file_path: str,
        old_string: str,
        new_string: str,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        self._logger.info("[Tool Call] EditTool")
        self._logger.info(f"file_path: {file_path}")
        self._logger.info(f"old_string: {old_string}")
        self._logger.info(f"new_string: {new_string}")

        if not Path(file_path).is_relative_to(self._source_directory):
            raise ToolException(
                f"The file {file_path} is outside the working directory"
            )

        if not Path(file_path).is_file():
            raise ToolException(f"The file {file_path} does not exists")

        text = Path(file_path).read_text(errors="replace")
        if text.count(old_string) != 1:
            raise ToolException("old_string is not unique or doesn't match exactly")
        new_text = text.replace(old_string, new_string)

        Path(file_path).write_text(new_text)

        return f"The file {file_path} has been edited successfully"
