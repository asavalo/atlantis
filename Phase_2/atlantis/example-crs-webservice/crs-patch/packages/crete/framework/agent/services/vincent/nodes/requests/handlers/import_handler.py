from pathlib import Path
import glob
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.vincent.nodes.requests.handlers.base_request_handler import (
    BaseRequestHandler,
)
from crete.framework.agent.services.vincent.functions import (
    LLMRequest,
)
from crete.framework.agent.services.vincent.code_inspector.functions import (
    append_line_num,
)


def _find_all_files_from_dir(directory: Path, filename: str) -> list[str]:
    return glob.glob(str(directory / "**" / filename), recursive=True)


C_EXTENSIONS = [
    ".c",
    ".cc",
    ".cxx",
    ".c++",
    ".C",
    ".cpp",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".h++",
    ".H",
    ".in",
]


def _check_if_target_is_c_file(target_name: str) -> bool:
    if Path(target_name).suffix in C_EXTENSIONS:
        return True
    return False


class ImportRequestHandler(BaseRequestHandler):
    def __init__(self, context: AgentContext):
        super().__init__(context)

    def handle_request(self, request: LLMRequest) -> str:
        assert request.targets is not None

        if len(request.targets) == 0:
            self.context["logger"].warning(
                f'"{request.raw}" seems not to follow the request guidelines'
            )
            # LLM requested with invalid format.
            return f'Your request "{request.raw}" seems not to follow the request rule. Check again your request.\n'

        requested_info_text = ""
        for filename in request.targets:
            files = _find_all_files_from_dir(
                self.context["pool"].source_directory, filename
            )

            if len(files) == 0:
                self.context["logger"].warning(
                    f'File "{filename}" was not found in the project.'
                )
                requested_info_text += f"The requested `{filename}` is not found or not available in the current project.\n\n"
                continue

            for filepath in files:
                if _check_if_target_is_c_file(filepath):
                    return f'You are using the "import" type request on the C/C++ source code (`{filename}`). This type of request is only allowed for Java projects. Check the "Information Request" section again.\n\n'

            for filepath in files:
                requested_info_text += self._create_prompt_from_file(Path(filepath))

        return requested_info_text

    def _create_prompt_from_file(self, target_path: Path) -> str:
        rel_path = target_path.relative_to(self.context["pool"].source_directory)

        if target_path.is_dir():
            return f"`{rel_path}` is a directory.\n"

        try:
            file_content = target_path.read_text(encoding="utf-8", errors="ignore")
        except UnicodeDecodeError:
            return f"It seems `{rel_path}` is not a human-readable text file.\n\n"

        if len(file_content) == 0:
            self.context["logger"].warning(f'"{target_path}" filesize is 0')
            return f'"{rel_path}" is an empty file.'

        import_statements = _extract_import_statements(file_content)

        if import_statements is None:
            return f"There is no import statements in `{rel_path}`\n\n"

        return f"Here are the import statements present in `{rel_path}`\nfilename:{rel_path}\n{import_statements}\n\n"


def _extract_import_statements(content: str) -> str | None:
    lines = [""] + content.splitlines(keepends=True)

    # Find the line that contains "package"
    start_line_num = None
    end_line_num = None

    for i, line in enumerate(lines):
        if "package" in line and ";" in line:
            start_line_num = i
            break

    if start_line_num is None:
        return None

    # Find the last line that contains "imports"
    for i, line in enumerate(lines):
        if "import" in line and ";" in line:
            end_line_num = i

    if end_line_num is None:
        return None

    if start_line_num >= end_line_num:
        return None

    return append_line_num(
        "".join(lines[start_line_num : end_line_num + 1]), start_line_num
    )
