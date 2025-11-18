from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.vincent.nodes.requests.handlers.base_request_handler import (
    BaseRequestHandler,
)
from crete.framework.agent.services.vincent.code_inspector import (
    VincentCodeInspector,
)
from crete.framework.agent.services.vincent.nodes.requests.models import (
    LLMRequest,
)
from crete.framework.agent.services.vincent.nodes.requests.functions import (
    aggregate_code_query_results,
)
from crete.framework.agent.services.vincent.code_inspector.functions import (
    get_text_lines_from_file,
)
from crete.framework.agent.services.vincent.code_inspector.models import (
    CodeQueryResult,
)
from pathlib import Path
import re


def _parse_request_target_file(raw_text: str) -> list[str]:
    pattern = r"\(file:`(.*?)`\)"

    # Use re.search to find the first occurrence of the pattern
    matches = re.findall(pattern, raw_text, re.DOTALL)

    return [match.strip() for match in matches]


def _parse_request_line_range(raw_text: str) -> list[tuple[int, int]]:
    pattern = r"\(line:(\d+)-(\d+)\)"

    # Use re.search to find the first occurrence of the pattern
    matches = re.findall(pattern, raw_text, re.DOTALL)

    return [(int(match[0]), int(match[1])) for match in matches]


class LineRequestHandler(BaseRequestHandler):
    def __init__(self, context: AgentContext, code_inspector: VincentCodeInspector):
        super().__init__(context)
        self.code_inspector = code_inspector

    def handle_request(self, request: LLMRequest) -> str:
        assert request.targets is not None

        if len(request.targets) == 0:
            self.context["logger"].warning(
                f'"{request.raw}" seems not to follow the request guidelines'
            )
            # LLM requested with invalid format.
            return f'Your request "{request.raw}" seems not to follow the request rule. Check again your request.\n\n'

        if len(request.targets) != 1:
            self.context["logger"].warning(
                f'"{request.raw}" contains more than one target file and line range...'
            )
            # LLM requested with invalid format.
            return f'Your request "{request.raw}" contains more than one target file and line range. Submit a fixed request according to the provided rule.\n\n'

        target_str = request.targets[0]

        target_files = _parse_request_target_file(target_str)
        target_line_ranges = _parse_request_line_range(target_str)

        failure_reason = self._verify_target_file(request, target_files)
        if failure_reason:
            return failure_reason

        target_filepath = Path(target_files[0])
        target_abs_path = self.context["pool"].source_directory / target_filepath

        failure_reason = self._verify_line_range(
            request, target_line_ranges, target_abs_path
        )
        if failure_reason:
            return failure_reason

        start_line, end_line = target_line_ranges[0]

        target_abs_path = self.context["pool"].source_directory / target_filepath

        snippet = get_text_lines_from_file(target_abs_path, start_line, end_line)

        if snippet is None:
            return f'Regarding the "{request.raw}", `{target_filepath}` is an empty file.\n\n'

        return aggregate_code_query_results(
            "",
            [
                CodeQueryResult(
                    abs_src_path=target_abs_path,
                    src_path=target_filepath,
                    snippet=snippet,
                    is_tree_sitter=False,
                )
            ],
        )

    def _verify_target_file(
        self, request: LLMRequest, target_files: list[str]
    ) -> str | None:
        if len(target_files) == 0:
            return f'Your request "{request.raw}" does not contain the valid file. Submit a fixed request according to the provided rule.\n\n'

        if len(target_files) != 1:
            return f'Your request "{request.raw}" contains more than one target file. You can request only one file per one request.\n\n'

        target_filepath = Path(target_files[0])

        if target_filepath.is_absolute():
            return f'Your request "{request.raw}" contains the absolute path for (file:`filename`) field. Submit a fixed request with a relative path according to the provided rule.\n\n'

        target_abs_path = self.context["pool"].source_directory / target_filepath

        if target_abs_path not in self.code_inspector.get_visited_src_list():
            return f'Regarding the request "{request.raw}", the `{target_filepath}` has not been found in the previous user-provided code information (i.e., "*filepath: ..." parts). Make SURE that the requested file is confirmed to **explicitly** exist in the previous request result.\n\n'

        if not (self.context["pool"].source_directory / target_filepath).exists():
            return f'Your request "{request.raw}" contains the invalid file that does not exist. You can submit [REQUEST:LINE] type requests only if the target file was found as it is in the previous request results.\n\n'

        return None

    def _verify_line_range(
        self,
        request: LLMRequest,
        line_ranges: list[tuple[int, int]],
        abs_src_path: Path,
    ) -> str | None:
        if len(line_ranges) == 0:
            return f"Your request \"{request.raw}\" does not contain a valid line range using the hyphen ('-'). Submit a fixed request according to the provided rule.\n\n"

        if len(line_ranges) != 1:
            return f'Your request "{request.raw}" contains more than one line range. You can request only one line range per one request.\n\n'

        start_line, end_line = line_ranges[0]

        lines = abs_src_path.read_text(encoding="utf-8", errors="ignore").splitlines(
            keepends=True
        )

        if start_line <= 0:
            return f'Regarding the request "{request.raw}", the start line ({start_line}) must be a valid integer for line number. Fix your request according to this information.\n\n'

        if end_line > len(lines):
            return f'Regarding the request "{request.raw}", the end line number ({end_line}) exceeds the maximum line number ({len(lines)}). Fix your request according to this information.\n\n'

        if start_line > end_line:
            return f'The request "{request.raw}" is invalid because the start line number ({start_line}) is larger than end line number ({end_line}). Fix your request according to this information.\n\n'

        return None
