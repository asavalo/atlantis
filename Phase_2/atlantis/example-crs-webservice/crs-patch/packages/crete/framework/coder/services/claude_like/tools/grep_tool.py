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
MAX_GREP_RESULT = 100


class GrepInput(BaseModel):
    pattern: str = Field(description="The regular expression pattern to search")
    path: Optional[str] = Field(
        description="The directory to search in (absolute path, default: working directory)"
    )
    include: Optional[str] = Field(description="The pattern to include (glob pattern)")


class GrepTool(BaseTool):
    name: str = "GrepTool"
    description: str = """Searches file contents using the given regular expression and returns the paths of files that match the pattern. The include parameter can be used to filter specific files. Used to search the contents of a file.

When to use this tool
- Used to find files with specific contents. It is especially recommended when searching for files that contain specific keywords in their contents.
- Tasks that require multiple uses of GlobTool or GrepTool are recommended to use dispatch_agent.

What outputs is expected by this tool
- List of files within the directory given by `path` that match the glob pattern `include` and contain the given regex `pattern` in their contents.

Note
- include must be a glob pattern such as `*.c` or `**/*.java`.
- pattern must be a regular expression such as `int|float|double` or `main\\s*\\(\\)`.
"""
    args_schema: Optional[ArgsSchema] = GrepInput
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
        include: Optional[str],
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        if self._is_subtool is True:
            self._logger.info("[Tool Call] GrepTool (by AgentTool)")
        else:
            self._logger.info("[Tool Call] GrepTool")
        self._logger.info(f"pattern: {pattern}")
        self._logger.info(f"path: {path}")
        self._logger.info(f"include: {include}")

        p = self._source_directory if path is None else Path(path)
        if not p.is_relative_to(self._source_directory):
            raise ToolException(f"The file {p} is outside the working directory")

        if not p.is_dir():
            raise ToolException(f"The file {p} is not a directory")

        param = ["grep", "-rliEe", pattern]
        if include is not None:
            param += ["--include", include]

        process = subprocess.Popen(
            param,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=p,
        )
        try:
            stdout, stderr = process.communicate(timeout=TIMEOUT)
            return_code = process.returncode
            if return_code == 1:
                return "No matching files found"

            if return_code != 0:
                raise ToolException(
                    f"Error occured while running grep : {stderr.decode(errors='replace')}"
                )

            path_list = list(
                map(
                    lambda x: str(p / Path(x)),
                    stdout.decode(errors="replace").strip().split("\n"),
                )
            )

            result = f"{len(path_list)} matching file{'' if len(path_list) == 1 else 's'} found\n"
            result += "\n".join(path_list[:MAX_GREP_RESULT])
            if len(path_list) > MAX_GREP_RESULT:
                result += f"\n(truncated, maximum {MAX_GREP_RESULT} results)"
            return result

        except subprocess.TimeoutExpired as _:
            raise ToolException("Error occured while reading file : Timeout")
