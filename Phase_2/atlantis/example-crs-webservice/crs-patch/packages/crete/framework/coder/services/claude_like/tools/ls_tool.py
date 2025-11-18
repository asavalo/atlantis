import os

from typing import Optional
from pathlib import Path

from pydantic import BaseModel, Field

from langchain_core.callbacks import (
    CallbackManagerForToolRun,
)

from langchain_core.tools import BaseTool, ToolException
from langchain_core.tools.base import ArgsSchema

from logging import Logger

MAX_LS_FILES = 1000


class LSInput(BaseModel):
    path: str = Field(description="The directory path to list (absolute path)")


class LSTool(BaseTool):
    name: str = "LS"
    description: str = """Lists the files in the given directory path.

When to use this tool
- Used to understand the directory structure at the given path.
- If you know the directory or the contents of the files to be searched, GlobTool or GrepTool is preferred.
"""
    args_schema: Optional[ArgsSchema] = LSInput
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
        path: str,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        if self._is_subtool is True:
            self._logger.info("[Tool Call] LSTool (by AgentTool)")
        else:
            self._logger.info("[Tool Call] LSTool")
        self._logger.info(f"Path: {path}")

        if not Path(path).is_relative_to(self._source_directory):
            raise ToolException(f"The file {path} is outside the working directory")

        if not Path(path).is_dir():
            raise ToolException(f"The file {path} is not a directory")

        file_tree = self.get_tree(path)
        result = "\n".join(file_tree[:MAX_LS_FILES])
        if len(file_tree) > MAX_LS_FILES:
            result = (
                result
                + f"The number of files and directories inside the path exceeds {MAX_LS_FILES}, so the latter part of the results has been truncated. Provide a more specific path or use other tools like GlobTool to narrow down the search results."
            )

        return result

    def get_tree(self, start_path: str) -> list[str]:
        result: list[str] = []
        start_depth = start_path.count(os.sep)

        for root, _, files in os.walk(start_path):
            depth = root.count(os.sep) - start_depth
            indent = "  " * depth
            dirname = os.path.basename(root)
            result.append(f"{indent}- {dirname}/")

            for f in sorted(files):
                result.append(f"{indent}  - {f}")
        return result
