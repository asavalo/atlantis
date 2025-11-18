from typing import Literal

from sarif.tools.codeql.common import get_query_path
from sarif.tools.codeql.query import Query

get_all_func_from_harnesses_c = Query(
    get_query_path("c", "get_all_func_from_harnesses.jinja2"),
    "c",
    required_params=["harness_names"],
)

get_all_func_from_harnesses_java = Query(
    get_query_path("java", "get_all_func_from_harnesses.jinja2"),
    "java",
    required_params=["harness_names"],
)


def get_all_func_from_harnesses(lang: Literal["c", "java"]) -> Query:
    if lang == "c":
        return get_all_func_from_harnesses_c
    elif lang == "java":
        return get_all_func_from_harnesses_java


forward_reachability_many_to_one_c = Query(
    get_query_path("c", "forward_reachability_many_to_one.jinja2"),
    "c",
    required_params=["source_filenames", "sink_function", "sink_filename"],
)

forward_reachability_many_to_one_java = Query(
    get_query_path("java", "forward_reachability_many_to_one.jinja2"),
    "java",
    required_params=["source_filenames", "sink_function", "sink_filename"],
)

forward_reachability_polycall = Query(
    get_query_path("java", "forward_reachability_polycall.jinja2"),
    "java",
    required_params=["source_filenames", "sink_function", "sink_filename"],
)


def forward_reachability_many_to_one(lang: Literal["c", "java"]) -> Query:
    if lang == "c":
        return forward_reachability_many_to_one_c
    elif lang == "java":
        # return forward_reachability_many_to_one_java
        return forward_reachability_polycall


forward_reachability_functions_to_function_c = Query(
    get_query_path("c", "forward_reachability_functions_to_function.jinja2"),
    "c",
    required_params=["sink_function", "sink_filename"],
    required_external=["function_coverage"],
)

forward_reachability_functions_to_function_java = Query(
    get_query_path("java", "forward_reachability_functions_to_function.jinja2"),
    "java",
    required_params=["sink_function", "sink_filename"],
    required_external=["function_coverage"],
)


def forward_reachability_functions_to_function(lang: Literal["c", "java"]) -> Query:
    if lang == "c":
        return forward_reachability_functions_to_function_c
    elif lang == "java":
        return forward_reachability_functions_to_function_java


sink_analysis_c = Query(
    get_query_path("c", "sink_analysis.ql"),
    "c",
    required_external=["sink_candidates"],
)

sink_analysis_java = Query(
    get_query_path("java", "sink_analysis.ql"),
    "java",
    required_external=["sink_candidates"],
)


def sink_analysis(lang: Literal["c", "java"]) -> Query:
    if lang == "c":
        return sink_analysis_c
    elif lang == "java":
        return sink_analysis_java


get_function_by_line_c = Query(
    get_query_path("c", "get_function_by_line.jinja2"),
    "c",
    required_params=["file_path", "start_line", "end_line"],
)

get_function_by_line_java = Query(
    get_query_path("java", "get_function_by_line.jinja2"),
    "java",
    required_params=["file_path", "start_line", "end_line"],
)


def get_function_by_line(lang: Literal["c", "java"]) -> Query:
    if lang == "c":
        return get_function_by_line_c
    elif lang == "java":
        return get_function_by_line_java


# Call graph generation
get_call_graph_c = Query(
    get_query_path("c", "get_call_graph.ql"),
    "c",
)

get_call_graph_java = Query(
    get_query_path("java", "get_call_graph.ql"),
    "java",
)


def get_call_graph(lang: Literal["c", "java"]) -> Query:
    if lang == "c":
        return get_call_graph_c
    elif lang == "java":
        return get_call_graph_java


get_abs_path_c = Query(
    get_query_path("c", "get_abs_path.jinja2"),
    "c",
    required_params=["relative_paths"],
)

get_abs_path_java = Query(
    get_query_path("java", "get_abs_path.jinja2"),
    "java",
    required_params=["relative_paths"],
)


def get_abs_path(lang: Literal["c", "java"]) -> Query:
    if lang == "c":
        return get_abs_path_c
    elif lang == "java":
        return get_abs_path_java


get_all_functions_c = Query(
    get_query_path("c", "get_all_functions.ql"),
    "c",
)

get_all_functions_java = Query(
    get_query_path("java", "get_all_functions.ql"),
    "java",
)


def get_all_functions(lang: Literal["c", "java"]) -> Query:
    if lang == "c":
        return get_all_functions_c
    elif lang == "java":
        return get_all_functions_java
