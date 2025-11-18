import random
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

SOURCE_EXTENSIONS = [
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
    ".java",
    ".in",
]


def _check_if_target_is_source_file(target_name: str) -> bool:
    for ext in SOURCE_EXTENSIONS:
        if ext in target_name:
            return True
    return False


class ReferenceRequestHandler(BaseRequestHandler):
    def __init__(self, context: AgentContext, code_inspector: VincentCodeInspector):
        super().__init__(context)
        self.code_inspector = code_inspector

    def handle_request(self, request: LLMRequest, max_snippet_num: int = 10) -> str:
        assert request.targets is not None

        if len(request.targets) == 0:
            self.context["logger"].warning(
                f'"{request.raw}" seems not to follow the request guidelines'
            )
            # LLM requested with invalid format.
            return f'Your request "{request.raw}" seems not to follow the request rule. Check again your request.\n'

        requested_info_text = ""

        for target_name in request.targets:
            if _check_if_target_is_source_file(target_name):
                return f'In "{request.raw}", `{target_name}` is a source code file. As described in Information Request section, you can use REFERENCE type request only with actual code, not a file.\n'
            query_results = self.code_inspector.get_references(target_name)

            if query_results is None:
                return f"It seems `{target_name}` is not found in the codebase. Make sure you are asking the code element that actually exists in the codebase as it is."

            if len(query_results) > max_snippet_num:
                # To avoid exceeding token lilmits,
                # randomly choose at most `max_snippet_num` snippets from the found snippets.
                query_results = random.sample(query_results, max_snippet_num)
                requested_info_text += f"Since there are too many code snippets that use `{target_name}` in the codebase, I provide {max_snippet_num} randomly selected snippets among the result.\n\n"

            requested_info_text = aggregate_code_query_results(
                requested_info_text, query_results
            )

        return requested_info_text
