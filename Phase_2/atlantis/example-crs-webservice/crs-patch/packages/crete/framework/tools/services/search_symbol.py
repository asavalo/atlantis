import re
from pathlib import Path

from langchain_core.tools import ArgsSchema, BaseTool
from pydantic import BaseModel, Field

from crete.commons.utils import add_line_numbers
from crete.framework.code_inspector.functions import search_symbol_in_codebase
from crete.framework.environment.functions import resolve_project_path
from crete.framework.insighter.contexts import InsighterContext
from crete.utils.tools.callbacks import LoggingCallbackHandler


class SearchSymbolInput(BaseModel):
    symbol_name: str = Field(
        description="""The symbol name to search for.
The query string should be a fixed string, not a regex.
The symbol name can be a function, variable, struct, enum, etc.
Use a concise symbol name. Don't add any additional information like the parameter types, return type, or keyword like "class".
"""
    )
    file_or_directory_path: str | None = Field(
        description="""The file path or directory path to search for the symbol.
If you specify the directory path, the search will be performed in the directory, recursively.
If not provided, the search will be performed in the entire codebase.
"""
    )


class SearchSymbolTool(BaseTool):
    name: str = "search_symbol"
    description: str = "Search for a symbol in the codebase."
    args_schema: ArgsSchema = SearchSymbolInput  # pyright: ignore[reportIncompatibleVariableOverride]

    def __init__(
        self, context: InsighterContext, source_directory: Path, with_line_number: bool
    ):
        super().__init__(callbacks=[LoggingCallbackHandler(context)])
        self._context = context
        self._source_directory = source_directory
        self._with_line_number = with_line_number

    def _run(self, symbol_name: str, file_or_directory_path: str | None = None) -> str:
        target_path = (
            resolve_project_path(
                Path(file_or_directory_path), self._source_directory, only_file=False
            )
            if file_or_directory_path
            else self._source_directory
        )
        if target_path is None:
            self._context["logger"].warning(
                f"Target path is not exist: {file_or_directory_path}"
            )
            return "Target path is not exist."

        try:
            node = search_symbol_in_codebase(
                self._context, _calibrate_symbol_name(symbol_name)
            )

        except Exception as e:
            self._context["logger"].error(
                f"Error occurred while searching for the symbol: {e}"
            )
            return (
                "Error occurred while searching for the symbol. Try with other input."
            )

        if node is None:
            return "Not Found"

        symbol_definition = (
            add_line_numbers(node.text, node.start_line + 1)
            if self._with_line_number
            else node.text
        )

        if node.file.is_relative_to(target_path):
            return symbol_definition
        else:
            return (
                symbol_definition
                + "\n\n"
                + "The symbol definition is located in other file: "
                + str(node.file.relative_to(self._source_directory))
            )


def _calibrate_symbol_name(symbol_name: str) -> str:
    m = re.match(r"^class\s+(.*)$", symbol_name)
    if m is not None:
        return m.group(1)
    return symbol_name
