from typing import Optional
from pathlib import Path

from pydantic import BaseModel, Field

from langchain_core.callbacks import (
    CallbackManagerForToolRun,
)

from langchain_core.tools import BaseTool, ToolException
from langchain_core.tools.base import ArgsSchema

from logging import Logger

MAX_GLOB_RESULT = 100


class GlobInput(BaseModel):
    pattern: str = Field(description="The glob pattern to search")
    path: Optional[str] = Field(
        description="The directory to search in (absolute path, default: working directory)"
    )


class GlobTool(BaseTool):
    name: str = "GlobTool"
    description: str = """Returns the paths of files that match the given glob pattern. Used to search for the name of a file.

When to use this tool
- Used to search for the name of a file. It is especially recommended when searching for files whose paths contain specific keywords or have specific extensions.
- Tasks that require multiple uses of GlobTool or GrepTool are recommended to use dispatch_agent.

Note
- pattern must be a glob pattern such as `*.c` or `**/*.java`.
"""
    args_schema: Optional[ArgsSchema] = GlobInput
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
        pattern: str,
        path: Optional[str],
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        if self._is_subtool is True:
            self._logger.info("[Tool Call] GlobTool (by AgentTool)")
        else:
            self._logger.info("[Tool Call] GlobTool")
        self._logger.info(f"pattern: {pattern}")
        self._logger.info(f"path: {path}")

        p = self._source_directory if path is None else Path(path)

        if not p.is_relative_to(self._source_directory):
            raise ToolException(f"The file {p} is outside the working directory")

        if not p.is_dir():
            raise ToolException(f"The file {p} is not a directory")

        glob_list: list[str] = []

        try:
            for elem in p.glob(pattern):
                glob_list.append(str(elem))
        except ValueError as e:
            raise ToolException(f"Error while globbing: {e}")

        if len(glob_list) == 0:
            return "No matching files found"

        result = f"{len(glob_list)} matching file{'' if len(glob_list) == 1 else 's'} found\n"

        result = "\n".join(glob_list[:MAX_GLOB_RESULT])

        if len(glob_list) > MAX_GLOB_RESULT:
            result += f"\n(truncated, maximum {MAX_GLOB_RESULT} results)"

        return result
