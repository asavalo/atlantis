import re
from pathlib import Path
from typing import TypeAlias

from langchain_core.tools import BaseTool
from pydantic import BaseModel

from crete.framework.environment.functions import resolve_project_path
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.language_parser.functions import get_declaration_by_line
from crete.utils.tools.callbacks import LoggingCallbackHandler


class CodeSearchResult(BaseModel):
    file: Path
    line_number: int
    declaration_name: str | None
    code_region: str


_FunctionName: TypeAlias = str
_Occurrences: TypeAlias = int


# TODO: This needs to search the entire codebase.
# As we do not have a pre-build index of files like AutoCodeRover, this would take too long.
# We'll need to implement a more efficient search mechanism.
# @tool
# def search_code(code: str) -> str:
#     """
#     Get the code that matches the given code snippet.
#     Searches entire codebase.

#     Returns declaration that contains the snippet.
#     Otherwise, returns region of code surrounding it.
#     """
#     return _search_code_impl(context, code)


class SearchCodeInFileTool(BaseTool):
    name: str = "search_code_in_file"
    description: str = (
        "Get the code that matches the given code snippet in the given file."
    )

    def __init__(self, context: InsighterContext):
        super().__init__(
            callbacks=[LoggingCallbackHandler(context)],
        )
        self._context = context

    def _run(self, code: str, file: str) -> str:
        """
        Get the code that matches the given code snippet in the given file.
        """
        return self._search_code_in_file_impl(self._context, code, file)

    def _search_code_in_file_impl(
        self,
        context: InsighterContext,
        code: str,
        file: str,
        result_show_limit: int = 3,
    ) -> str:
        file_path = resolve_project_path(Path(file), context["pool"].source_directory)
        if not file_path:
            raise FileNotFoundError(f"File does not exist: {file_path}")

        searched_line_and_code: list[tuple[int, str]] = (
            self._get_code_region_containing_code(code, file_path)
        )

        if not searched_line_and_code:
            raise ValueError(f"Code not find code {code} in file {file}.")

        search_result: list[CodeSearchResult] = []
        for searched in searched_line_and_code:
            line_number, code_region = searched
            declaration_name = get_declaration_by_line(
                context["language_parser"],
                context,
                file_path,
                line_number,
            )
            search_result.append(
                CodeSearchResult(
                    file=file_path,
                    line_number=line_number,
                    declaration_name=(
                        declaration_name[0] if declaration_name is not None else None
                    ),
                    code_region=code_region,
                )
            )

        if not search_result:
            return ""

        output: str = (
            f"Found {len(search_result)} snippets with code {code} in file {file}:\n\n"
        )
        if len(search_result) > result_show_limit:
            output += "They appeared in the following methods:\n"
            output += self._collapse_search_results_to_method_level(
                search_result, context["pool"].source_directory
            )
        else:
            for i, result in enumerate(search_result):
                result_str = self._search_result_to_tagged_string(
                    result, context["pool"].source_directory
                )
                output += f"- Search result {i + 1}:\n```\n{result_str}\n```\n"

        return output

    def _get_code_region_containing_code(
        self,
        code: str,
        file_path: Path,
    ) -> list[tuple[int, str]]:
        file_content = file_path.read_text(errors="replace")
        code_context_size = 3
        pattern = re.compile(re.escape(code))
        occurrences: list[tuple[int, str]] = []
        for match in pattern.finditer(file_content):
            matched_start_position = match.start()
            matched_line_number = file_content.count("\n", 0, matched_start_position)

            file_content_lines = file_content.splitlines()

            window_start_index = max(0, matched_line_number - code_context_size)
            window_end_index = min(
                len(file_content_lines), matched_line_number + code_context_size + 1
            )

            code_context = "\n".join(
                file_content_lines[window_start_index:window_end_index]
            )
            occurrences.append((matched_line_number, code_context))

        return occurrences

    def _collapse_search_results_to_method_level(
        self,
        search_results: list[CodeSearchResult],
        project_directory: Path,
    ) -> str:
        result: dict[Path, dict[_FunctionName, _Occurrences]] = {}
        for search_result in search_results:
            if search_result.file not in result:
                result[search_result.file] = {}
            function_string = (
                search_result.declaration_name
                if search_result.declaration_name is not None
                else "Not in a function"
            )
            if function_string not in result[search_result.file]:
                result[search_result.file][function_string] = 1
            else:
                result[search_result.file][function_string] += 1
        result_string: str = ""
        for file, functions in result.items():
            relative_path = file.relative_to(project_directory)
            file_part = f"<file>{relative_path}</file>"
            for function, count in functions.items():
                if function == "Not in a function":
                    function_part = function
                else:
                    function_part = f" <function>{function}</function>"
                result_string += f"- {file_part}{function_part} ({count} matches)\n"
        return result_string

    def _search_result_to_tagged_file(
        self,
        search_result: CodeSearchResult,
        project_directory: Path,
    ) -> str:
        relative_path = search_result.file.relative_to(project_directory)
        return f"<file>{relative_path}</file>"

    def _search_result_to_tagged_declaration(
        self,
        search_result: CodeSearchResult,
        project_directory: Path,
    ) -> str:
        prefix = self._search_result_to_tagged_file(search_result, project_directory)
        if search_result.declaration_name is None:
            return f"{prefix} Not in a function"
        else:
            return f"{prefix} <function>{search_result.declaration_name}</function>"

    def _search_result_to_tagged_string(
        self,
        search_result: CodeSearchResult,
        project_directory: Path,
    ) -> str:
        prefix = self._search_result_to_tagged_declaration(
            search_result, project_directory
        )
        return f"{prefix}\n```\n{search_result.code_region}\n```"
