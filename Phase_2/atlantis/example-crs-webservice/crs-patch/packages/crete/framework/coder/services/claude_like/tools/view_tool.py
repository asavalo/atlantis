import subprocess
from logging import Logger
from pathlib import Path
from typing import Optional

from langchain_core.callbacks import (
    CallbackManagerForToolRun,
)
from langchain_core.tools import BaseTool, ToolException
from langchain_core.tools.base import ArgsSchema
from pydantic import BaseModel, Field

TIMEOUT = 10
MAX_OUTPUT_SIZE = 20000


class ViewInput(BaseModel):
    file_path: str = Field(description="The file path to read (absolute path)")
    offset: Optional[int] = Field(
        description="The start line number to read from. It's 1-based index. Only provide if the file is too large"
    )
    limit: Optional[int] = Field(
        description="The number of lines to read. Only provide if the file is too large."
    )


class ViewTool(BaseTool):
    name: str = "View"
    description: str = """Reads a file from the given file path.

When to use this tool
- Used to read the entire or part of a file's contents.

Notes
- By default, it reads up to 1000 lines starting from the beginning of the file.
- You can optionally specify a line offset and limit if the file is too large to read or you want to read a specific part of the file.
- The file content will be returned with line numbers.
"""
    args_schema: Optional[ArgsSchema] = ViewInput
    return_direct: bool = False

    def __init__(
        self, logger: Logger, source_directory: Path, is_subtool: bool = False
    ):
        super().__init__()
        self._logger = logger
        self._source_directory = source_directory
        self._is_subtool = is_subtool

    def _run(
        self,
        file_path: str,
        offset: Optional[int],
        limit: Optional[int],
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        if self._is_subtool is True:
            self._logger.info("[Tool Call] ViewTool (by AgentTool)")
        else:
            self._logger.info("[Tool Call] ViewTool")
        self._logger.info(f"file_path: {file_path}")
        self._logger.info(f"offset: {offset}")
        self._logger.info(f"limit: {limit}")

        if not Path(file_path).is_relative_to(self._source_directory):
            raise ToolException(
                f"The file {file_path} is outside the working directory"
            )

        offset = 0 if offset is None or offset < 1 else offset - 1
        limit = 1000 if limit is None or limit < 0 else limit

        if not Path(file_path).is_file():
            raise ToolException(f"The file {file_path} does not exist")

        process = subprocess.Popen(
            ["cat", "-n", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout, stderr = process.communicate(timeout=TIMEOUT)
            return_code = process.returncode
            if return_code != 0:
                raise ToolException(
                    f"Error occured while reading file : {stderr.decode(errors='replace')}"
                )

            content = "\n".join(
                map(
                    lambda x: x[:1000],
                    stdout.decode(errors="replace").split("\n")[
                        offset : offset + limit
                    ],
                )
            )
            if len(content) > MAX_OUTPUT_SIZE:
                raise ToolException(
                    f"The file content ({len(content)} characters) exceeds {MAX_OUTPUT_SIZE} characters. Set offset and limit to read only part of the file, or use GrepTool to search for specific content within the file."
                )

            return content

        except subprocess.TimeoutExpired as _:
            raise ToolException("Error occured while reading file : Timeout")
