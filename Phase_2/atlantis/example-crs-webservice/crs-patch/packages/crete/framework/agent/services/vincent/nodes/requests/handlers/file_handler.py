from pathlib import Path
import glob
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.vincent.nodes.requests.handlers.base_request_handler import (
    BaseRequestHandler,
)

from crete.framework.agent.services.vincent.functions import (
    LLMRequest,
)

MAX_FILE_LEN = 10000


def _find_all_files_from_dir(directory: Path, filename: str) -> list[str]:
    return glob.glob(str(directory / "**" / filename), recursive=True)


def _append_line_num(content: str) -> str:
    assert content is not None

    return "\n".join(f"{i + 1}:{line}" for i, line in enumerate(content.splitlines()))


class FileRequestHandler(BaseRequestHandler):
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

        if len(file_content) > MAX_FILE_LEN:
            self.context["logger"].warning(
                f'length of the file "{target_path}" is larger than {MAX_FILE_LEN}.'
            )

        return (
            f"Here is the content of `{rel_path}`\n{_append_line_num(file_content)}\n\n"
        )
