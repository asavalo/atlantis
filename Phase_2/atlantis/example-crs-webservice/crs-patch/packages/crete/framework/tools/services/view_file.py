from pathlib import Path

from langchain_core.tools import ArgsSchema, BaseTool
from pydantic import BaseModel, Field

from crete.commons.utils import add_line_numbers
from crete.framework.environment.functions import resolve_project_path
from crete.framework.insighter.contexts import InsighterContext
from crete.utils.tools.callbacks import LoggingCallbackHandler


class ViewFileInput(BaseModel):
    file_path: str = Field(
        description="The file path to read. It could be an absolute path, a relative path, or a file name but be specific as possible"
    )
    offset: int | None = Field(
        description="The start line number to read from. It's 1-based index. Only provide if the file is too large."
    )
    limit: int | None = Field(
        description="The number of lines to read. Only provide if the file is too large."
    )


def _get_description(with_line_number: bool) -> str:
    template = """Reads a file from the given file path.

    Usage:
    - By default, it reads up to 1000 lines starting from the beginning of the file
    - You can optionally specify a line offset and limit if the file is too large to read or you want to read a specific part of the file
    - The file content will be returned {with_line_number_prompt}
    """

    return template.format(
        with_line_number_prompt="with line numbers"
        if with_line_number
        else "without line numbers"
    )


class ViewFileTool(BaseTool):
    name: str = "view_file"
    args_schema: ArgsSchema | None = ViewFileInput

    def __init__(self, context: InsighterContext, with_line_number: bool):
        super().__init__(
            callbacks=[LoggingCallbackHandler(context)],
            description=_get_description(with_line_number),
        )
        self._context = context
        self._with_line_number = with_line_number

    def _run(
        self, file_path: str, offset: int | None = None, limit: int | None = None
    ) -> str:
        resolved_path = resolve_project_path(
            Path(file_path), self._context["pool"].source_directory
        )
        if not resolved_path:
            self._context["logger"].warning(f"File does not exist: {file_path}")
            return f"File does not exist: {file_path}"

        lines = resolved_path.read_text(errors="replace").rstrip().split("\n")

        offset = offset - 1 if offset is not None else 0
        limit = min(limit or len(lines), 1000)

        code_snippet = "\n".join(lines[offset : offset + limit])
        if not self._with_line_number:
            return code_snippet
        return add_line_numbers(code_snippet, offset + 1)
