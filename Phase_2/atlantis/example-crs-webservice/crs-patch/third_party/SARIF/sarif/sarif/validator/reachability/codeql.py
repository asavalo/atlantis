from pathlib import Path
from typing import Literal

from loguru import logger

from sarif.context import SarifCacheManager, SarifEnv
from sarif.models import CP, CodeLocation, Function, FuzzerCoverage, Harness, SarifInfo
from sarif.tools.codeql.database import Database
from sarif.tools.codeql.queries import (
    forward_reachability_functions_to_function,
    forward_reachability_many_to_one,
    get_all_func_from_harnesses,
    get_all_functions,
    get_call_graph,
)
from sarif.utils.cache import cache_method_with_attrs
from sarif.validator.reachability.base import BaseReachabilityAnalyser
from sarif.validator.reachability.callgraph import CallGraph, CallType


def _safe_parse_codeql_res(res: dict) -> dict:
    for key in res.keys():
        match key:
            case "func" | "file" | "file_abs" | "class_name" | "sig" | "method_desc":
                if res[key] == "UNKNOWN":
                    # logger.warning(f"res: {res}")
                    raise ValueError(f"Missing required field: {key}")
            case "start_line" | "end_line":
                if res[key] == "UNKNOWN":
                    res[key] = -1
    return res


class CodeQLReachabilityAnalyser(BaseReachabilityAnalyser):
    # SUPPORTED_MODES = Literal["callgraph", "forward", "backward", "fuzzer-enhanced"]
    SUPPORTED_MODES = Literal["callgraph"]
    name = "codeql"

    def __init__(
        self,
        cp: CP,
        *,
        db_path: Path | None = None,
    ):
        super().__init__(cp)

        if db_path is None:
            db_path = SarifEnv().codeql_db_path

        self.db_path = db_path

    @cache_method_with_attrs(mem=SarifCacheManager().memory, attr_names=["cp"])
    def _get_whole_callgraph(self) -> CallGraph:
        query = get_call_graph(self.cp.language)

        query_res = query.run(
            database=self.db_path,
        )

        return CallGraph.from_codeql(query_res.parse(), self.cp.language)

    @cache_method_with_attrs(mem=SarifCacheManager().memory, attr_names=["cp"])
    def _get_all_functions(self) -> list[Function]:
        query = get_all_functions(self.cp.language)

        query_res = query.run(
            database=self.db_path,
        )

        all_functions = []
        for res in query_res.parse():
            try:
                parsed_res = _safe_parse_codeql_res(res)
            except ValueError as e:
                # logger.warning(f"Error parsing codeql result: {e}")
                continue

            sig = parsed_res["sig"] if "sig" in parsed_res else None
            class_name = (
                parsed_res["class_name"] if "class_name" in parsed_res else None
            )
            method_desc = (
                parsed_res["method_desc"] if "method_desc" in parsed_res else None
            )

            function = Function(
                func_name=parsed_res["func"],
                file_name=parsed_res["file"],
                start_line=parsed_res["start_line"],
                end_line=parsed_res["end_line"],
                func_sig=sig,
                class_name=class_name,
                method_desc=method_desc,
            )

            all_functions.append(function)

        return all_functions

    def init_whole_callgraph(self) -> None:
        if self.whole_callgraph is None:
            self.whole_callgraph = self._get_whole_callgraph()
            all_functions = self._get_all_functions()
            for function in all_functions:
                self.whole_callgraph.add_function(function)

    def merge_callgraph(self, other_analyser: BaseReachabilityAnalyser) -> None:
        if self.whole_callgraph is None or other_analyser.whole_callgraph is None:
            raise ValueError("Callgraph is not initialized")

        self.whole_callgraph.merge_callgraph(other_analyser.whole_callgraph)
        self.split_callgraph()

    def reachability_analysis(
        self,
        sink_location: CodeLocation,
        harness: Harness | None = None,
        *,
        mode: SUPPORTED_MODES = "callgraph",
    ) -> bool:
        if sink_location.function is None or sink_location.function.func_name == "":
            raise ValueError("Function is required in CodeQLReachabilityAnalyser")

        match mode:
            case "callgraph":
                reachable_functions = self.get_all_reachable_funcs(harness)
                return self._check_reachable(
                    reachable_functions, sink_location.function, harness
                )
            case _:
                raise ValueError(f"Unsupported mode: {mode}")
