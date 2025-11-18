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
from crete.framework.agent.services.vincent.code_inspector.models import (
    CodeQueryResult,
)
from crete.framework.language_parser.services.ctags.models import CtagEntry
import re


def _extract_name_and_class_from_request(
    raw_request: str,
) -> dict[str, list[str]] | None:
    pattern = r"\((\w+):`([^`]+)`\)"

    matches = re.findall(pattern, raw_request)

    if len(matches) == 0:
        return None

    result: dict[str, list[str]] = {"name": [], "class": [], "invalid": []}

    for match in matches:
        if match[0] == "name":
            result["name"].append(match[1])
        elif match[0] == "class":
            result["class"].append(match[1])
        else:
            result["invalid"].append(match[1])

    return result


class JavaDefinitionRequestHandler(BaseRequestHandler):
    def __init__(self, context: AgentContext, code_inspector: VincentCodeInspector):
        super().__init__(context)
        self.code_inspector = code_inspector

    def handle_request(self, request: LLMRequest) -> str:
        assert request.targets is not None

        if self.code_inspector.lang != "jvm":
            return 'You are using the "java_definition" type request on the C/C++ project. This type of request is only allowed for Java projects. Check the "Information Request" section again.\n\n'

        assert len(request.targets) == 1

        name_class_dict = _extract_name_and_class_from_request(request.raw)

        if name_class_dict is None:
            return f'In your request "{request.raw}", you are not using a valid (name:`target name`) and (class:`target class`) within the [REQUEST:java_definition] ... [REQUEST:java_definition] tag. Check the "Information Request" section again.\n\n'

        if len(name_class_dict["invalid"]) != 0:
            return f'Your request "{request.raw}" contains invalid syntax regarding "{name_class_dict["invalid"]}". Check the "Information Request" section again and fix your request accordingly.\n\n'

        if len(name_class_dict["name"]) != 1:
            return f'The request "{request.raw}" contains no (name:`target name`) or more than one (name:`target name`). You must contain only one (name:`target name`) within the [REQUEST:java_definition] ... [REQUEST:java_definition] tag. Check the "Information Request" section again.\n\n'

        if len(name_class_dict["class"]) != 1:
            return f'The request "{request.raw}" contains no (class:`target class`) or more than one (class:`target class`). You must contain only one (class:`target class`) within the [REQUEST:java_definition] ... [REQUEST:java_definition] tag. Check the "Information Request" section again.\n\n'

        target_name = name_class_dict["name"][0]
        class_name = name_class_dict["class"][0]

        if check_if_fully_qualified_name(target_name):
            return f'In your request "{request.raw}", the `{target_name}` looks like a fully qualified name. Check the "Information Request" section again and submit the request with a simple name accordingly.\n\n'

        if check_if_fully_qualified_name(class_name):
            return f'In your request "{request.raw}", the `{class_name}` looks like a fully qualified name. Check the "Information Request" section again and submit the request with a simple name accordingly.\n\n'

        entries = self.code_inspector.ctags_parser.get_tag_entries_by_name(target_name)
        class_entries = self.code_inspector.ctags_parser.get_tag_entries_by_name(
            class_name
        )

        if len(class_entries) == 0:
            return f'In your request "{request.raw}", it seems `{class_name}` does not exist in the project or is not available due to the failure of our information retrieval system. Make sure the `{class_name}` actually exists in the project as it is, or try to proceed without the information if you are definitely sure about its existence.\n\n'

        if len(entries) == 0:
            return f'In your request "{request.raw}", it seems `{target_name}` does not exist in the project or is not available due to the failure of our information retrieval system. Make sure the `{target_name}` actually exists in the project as it is, or try to proceed without the information if you are definitely sure about its existence.\n\n'

        target_entries: list[CtagEntry] = []
        for entry in entries:
            if entry.scope is None:
                continue

            if entry.scope == class_name:
                target_entries.append(entry)

        if len(target_entries) == 0:
            return f'In your request "{request.raw}", there is no `{target_name}` wihtin the scope of `{class_name}`. Make sure that `{class_name}` contains the `{target_name}`.\n\n'

        query_results = self.code_inspector.get_definition(target_name)

        if query_results is None:
            return f'In your request "{request.raw}", getting the definition of `{target_name}` has failed due to the internal system failure. Try to proceed without the information.\n\n'

        query_results_in_scope: list[CodeQueryResult] = []

        for query_result in query_results:
            for target_entry in target_entries:
                if (
                    target_entry.abs_src_path != query_result.abs_src_path
                    or query_result.snippet.start_line > target_entry.line
                    or query_result.snippet.end_line < target_entry.line
                ):
                    continue

                query_results_in_scope.append(query_result)

        if len(query_results_in_scope) == 0:
            return f'Regarding the request "{request.raw}", getting the definition of `{target_name}` has failed due to the internal system failure. Use the [REQUEST:definition] type request instead, or try to proceed without the information.\n\n'

        return aggregate_code_query_results("", query_results_in_scope)
