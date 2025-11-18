import shlex
from pathlib import Path

from langchain_core.tools import ArgsSchema, BaseTool
from pydantic import BaseModel, Field
from python_ripgrep import RIPGREP_EXECUTABLE_FILE

from crete.commons.interaction.exceptions import CommandInteractionError
from crete.commons.interaction.functions import run_command
from crete.commons.logging.contexts import LoggingContext
from crete.framework.environment.functions import resolve_project_path
from crete.utils.tools.callbacks import LoggingCallbackHandler


class SearchStringInput(BaseModel):
    string: str = Field(
        description="The string to search for. The string should be a fixed string, not a regex."
    )
    file_or_directory_path: str | None = Field(
        description="""The file path or directory path to search for the string.
If you specify the directory path, the search will be performed in the directory, recursively.
If not provided, the search will be performed in the entire codebase.
"""
    )


class SearchStringTool(BaseTool):
    name: str = "search_string"
    description: str = """Search for a string in the codebase.

    Usage:
    - Use this tool to search for a string in the codebase.
    - If you want to search for a string in a specific directory, provide the directory path.
    - If you want to search for a string in the entire codebase, do not provide the directory path.
"""
    args_schema: ArgsSchema = SearchStringInput  # pyright: ignore[reportIncompatibleVariableOverride]

    def __init__(self, context: LoggingContext, source_directory: Path):
        super().__init__(callbacks=[LoggingCallbackHandler(context)])
        self._source_directory = source_directory
        self._logger = context["logger"]

    def _run(self, string: str, file_or_directory_path: str | None = None) -> str:
        target_path = (
            resolve_project_path(
                Path(file_or_directory_path), self._source_directory, only_file=False
            )
            if file_or_directory_path
            else self._source_directory
        )
        if target_path is None:
            self._logger.warning(f"Target path is not exist: {file_or_directory_path}")
            return "Target path is not exist."

        try:
            stdout, _stderr = run_command(
                (
                    f"{RIPGREP_EXECUTABLE_FILE} -nF {shlex.quote(string)} {target_path} | sed 's|{target_path}/||'",
                    Path("."),
                ),
            )
        except CommandInteractionError as e:
            self._logger.error(f"RIPGREP failed: {e.stderr}")
            return (
                "Error occurred while searching for the string. Try with other input."
            )

        if not stdout:
            return "Not Found"

        lines = stdout.splitlines()
        if len(lines) > 100:
            return f"""Too many files. Please specify a more specific path. This is the first 100 lines of the search result.

{"\n".join(lines[:100])}
"""

        return "\n".join(lines)
