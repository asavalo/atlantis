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
    check_if_fully_qualified_name,
)
from crete.framework.agent.services.vincent.code_inspector.functions import (
    get_text_lines_from_file,
)
from crete.framework.agent.services.vincent.code_inspector.models import (
    CodeQueryResult,
)
from crete.framework.code_inspector.functions import search_string_in_source_directory
from pathlib import Path

GET_DEFINITION_FAIL_SAFE_WINDOW = 5


def _check_prefix_in_target_name(target_name: str) -> bool:
    name_splits = target_name.split()
    if "struct" in name_splits or "union" in name_splits:
        return True
    return False


class DefinitionRequestHandler(BaseRequestHandler):
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

        requested_info_text = ""
        failed_cases: list[str] = []

        for target_name in request.targets:
            if _check_prefix_in_target_name(target_name):
                return f'In your request "{request.raw}", the `{target_name}` contains a prefix (i.e., "struct" or "union") within it. Check the "Information Request" section again and submit the request without the prefix accordingly.\n\n'

            if "`" in target_name:
                return f'In your request "{request.raw}", you are not using a valid (name:`target name`) within the [REQUEST:definition] ... [REQUEST:definition] tag. Check the "Information Request" section again.\n\n'

            if self.code_inspector.lang == "jvm" and check_if_fully_qualified_name(
                target_name
            ):
                return f'In your request "{request.raw}", the `{target_name}` looks like a fully qualified name. Check the "Information Request" section again and submit the request with a simple name accordingly.\n\n'
            query_results = self.code_inspector.get_definition(target_name)

            if query_results is None:
                self.context["logger"].warning(
                    f'get_definition failed for `{target_name}` (raw: "{request.raw}")'
                )
                failed_cases.append(target_name)
                continue

            requested_info_text = aggregate_code_query_results(
                requested_info_text, query_results
            )

        for target_name in failed_cases:
            requested_info_text += self._handle_ctags_failure(target_name)

        return requested_info_text

    def _handle_ctags_failure(self, target_name: str) -> str:
        self.context["logger"].warning(f"`{target_name}` is not found")

        grep_results = search_string_in_source_directory(
            self.context["pool"].source_directory, target_name, log_output=False
        )

        if len(grep_results) == 0:
            self.context["logger"].warning(
                f'no string "{target_name}" exists in the codebase.'
            )
            return f"It seems `{target_name}` is not available in the codebase.\nMake sure that you are asking the code that exists in the project as it is.\nIf you are sure that the code does exist, then retrieving `{target_name}` is not possible due to the sandboxed environment.\n\n"

        interesting_srcs: set[Path] = {grep_result[0] for grep_result in grep_results}
        query_results: list[CodeQueryResult] = []

        for src_path in interesting_srcs:
            def_likely_lines = self.code_inspector.get_definition_likely_lines(
                src_path, target_name
            )

            if def_likely_lines is None:
                continue

            for def_likely_line in def_likely_lines:
                snippet = get_text_lines_from_file(
                    src_path,
                    def_likely_line[0] - GET_DEFINITION_FAIL_SAFE_WINDOW,
                    def_likely_line[1] + GET_DEFINITION_FAIL_SAFE_WINDOW,
                )

                if snippet is None:
                    continue

                query_results.append(
                    CodeQueryResult(
                        abs_src_path=src_path,
                        src_path=src_path.relative_to(
                            self.context["pool"].source_directory
                        ),
                        snippet=snippet,
                        is_tree_sitter=False,
                    )
                )

        if len(query_results) == 0:
            return f"It seems `{target_name}` is not available in the codebase due to the internal system failure.\n"

        prompt = f"The definition of `{target_name}` cannot be directly retrieved due to the internal failure.\n"
        prompt += f"Instead, I provide definition-likely snippets for `{target_name}` as follows:\n\n"
        prompt += aggregate_code_query_results("", query_results)

        return prompt
