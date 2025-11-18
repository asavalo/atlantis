import re
from crete.framework.agent.services.vincent.code_inspector.models import CodeQueryResult


def aggregate_code_query_results(
    result_text: str, definitions: list[CodeQueryResult]
) -> str:
    for query_result in definitions:
        result_text += (
            f"*filepath: {query_result.src_path}\n{query_result.snippet.text}\n"
        )

    return result_text


def check_if_fully_qualified_name(target_name: str) -> bool:
    # Java identifier: starts with a letter or underscore, followed by letters/digits/underscores
    identifier = r"[a-zA-Z_][a-zA-Z0-9_]*"
    # Fully qualified name: one or more identifiers separated by dots
    pattern = rf"^{identifier}(\.{identifier})+$"
    return re.match(pattern, target_name) is not None
