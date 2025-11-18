from networkx.exception import NodeNotFound
from loguru import logger
from .callgraph import CallGraph
from .models import Function


def get_rechable_function_with_line(
    callgraph: CallGraph, filepath: str, line: int, include_uncertain: bool = False
) -> Function | None:
    if include_uncertain:
        all_rechable_functions: list[Function] = callgraph.get_all_reachable_funcs()
    else:
        all_rechable_functions: list[Function] = (
            callgraph.get_all_strong_reachable_funcs()
        )

    for function in all_rechable_functions:
        if function.file_name.endswith(filepath):
            if (function.start_line <= line) and (function.end_line >= line):
                return function
    return None


def get_subgraph(callgraph: CallGraph, function: Function) -> CallGraph | None:
    if not callgraph.is_reachable(function):
        return None

    return callgraph.get_target_callgraph(function)


def _get_paths_all(callgraph: CallGraph, function: Function) -> list[list[Function]]:
    if callgraph.is_reachable(function):
        return callgraph.get_all_paths(callgraph.get_entrypoint(), function)
    return list()


def get_paths(
    callgraph: CallGraph, function: Function, include_uncertain: bool = False
) -> list[list[Function]]:
    try:
        if include_uncertain:
            return _get_paths_all(callgraph, function)
        return _get_paths_all(callgraph.get_strong_callgraph(), function)
    except NodeNotFound:
        return list()

    except Exception as e:
        logger.warning(f"Unexpected error - {e}")
        return list()


def _get_shortest_path(callgraph: CallGraph, function: Function) -> list[Function]:
    return callgraph.get_shortest_path(callgraph.get_entrypoint(), function)


def get_shortest_path(
    callgraph: CallGraph, function: Function, include_uncertain: bool = False
) -> list[Function]:
    try:
        if include_uncertain:
            return _get_shortest_path(callgraph, function)
        return _get_shortest_path(callgraph.get_strong_callgraph(), function)
    except NodeNotFound:
        return list()

    except Exception as e:
        logger.warning(f"Unexpected error - {e}")
        return list()
