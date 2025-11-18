import itertools
from pathlib import Path
from typing import Literal

from loguru import logger

from sarif.context import SarifCacheManager, SarifEnv
from sarif.models import CP, CodeLocation, Function, Harness
from sarif.tools.codeql.queries import (
    get_all_functions,
    get_call_graph,
    get_call_graph_conditional,
    get_call_graph_only_from_harnesses,
    get_direct_call_graph,
)
from sarif.validator.reachability.base import BaseReachabilityAnalyser
from sarif.validator.reachability.callgraph import CallGraph

CHUNK_SIZE = 1000000


def _safe_parse_codeql_res(res: dict) -> dict:
    for key in res.keys():
        match key:
            case "func" | "file" | "file_abs" | "sig" | "method_desc":
                if res[key] == "UNKNOWN":
                    # logger.warning(f"res: {res}")
                    raise ValueError(f"Missing required field: {key}")
            case "class_name":
                if res[key] == "UNKNOWN":
                    res[key] = None if SarifEnv().cp.language == "c" else ""
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

    def _get_whole_callgraph(self) -> CallGraph:
        call_edge_generator = self._get_whole_callgraph_generator()
        return CallGraph.from_codeql_generator(call_edge_generator, self.cp.language)

    def _get_whole_callgraph_generator(self):
        if SarifEnv().cp.language in ["jvm", "java"]:
            try:
                query = get_call_graph(self.cp.language)
                query_res = query.run(database=self.db_path, timeout=1200)
            except Exception as e:
                logger.error(f"Error getting entire callgraph: {e}")
                logger.info("Trying to get callgraph only from harnesses")

                query = get_call_graph_only_from_harnesses(self.cp.language)
                query_res = query.run(
                    database=self.db_path,
                    params={
                        "harness_paths": [
                            harness.path.as_posix() for harness in self.cp.harnesses
                        ]
                    },
                    timeout=1200,
                )
        else:
            try:
                query = get_call_graph_conditional(self.cp.language)
                query_res = query.run(
                    database=self.db_path,
                    params={
                        "harness_paths": [
                            harness.path.as_posix() for harness in self.cp.harnesses
                        ],
                    },
                    timeout=1200,
                )
            except Exception as e:
                logger.error(f"Error getting conditional callgraph: {e}")
                logger.info("Trying to get callgraph only from harnesses")

                try:
                    query = get_call_graph_only_from_harnesses(self.cp.language)
                    query_res = query.run(
                        database=self.db_path,
                        params={
                            "harness_paths": [
                                harness.path.as_posix() for harness in self.cp.harnesses
                            ]
                        },
                        timeout=1200,
                    )
                except Exception as e:
                    logger.error(f"Error getting harness only callgraph: {e}")
                    logger.info("Trying to get direct callgraph")

                    query = get_direct_call_graph(self.cp.language)
                    query_res = query.run(database=self.db_path, timeout=1200)

        # Yield each call edge as parsed from query results
        for res in query_res.parse():
            try:
                parsed_res = CallGraph._safe_parse_codeql_res(res)
                yield parsed_res
            except ValueError as e:
                logger.warning(f"Error parsing codeql result: {e}")
                continue

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
                file_name=parsed_res["file_abs"],
                start_line=parsed_res["start_line"],
                end_line=parsed_res["end_line"],
                func_sig=sig,
                class_name=class_name,
                method_desc=method_desc,
            )

            all_functions.append(function)

        return all_functions

    def _get_all_functions_generator(self):
        query = get_all_functions(self.cp.language)
        query_res = query.run(database=self.db_path)

        for res in query_res.parse():
            try:
                parsed_res = _safe_parse_codeql_res(res)
            except ValueError as e:
                continue

            sig = parsed_res["sig"] if "sig" in parsed_res else None
            class_name = (
                parsed_res["class_name"] if "class_name" in parsed_res else None
            )
            method_desc = (
                parsed_res["method_desc"] if "method_desc" in parsed_res else None
            )

            yield Function(
                func_name=parsed_res["func"],
                file_name=parsed_res["file_abs"],
                start_line=parsed_res["start_line"],
                end_line=parsed_res["end_line"],
                func_sig=sig,
                class_name=class_name,
                method_desc=method_desc,
            )

    def _add_all_functions_using_chunks(self, chunk_size: int = CHUNK_SIZE) -> None:
        def chunked(iterable, size):
            iterator = iter(iterable)
            while True:
                chunk = list(itertools.islice(iterator, size))
                if not chunk:
                    break
                yield chunk

        function_generator = self._get_all_functions_generator()
        total_added = 0

        for chunk in chunked(function_generator, chunk_size):
            self.whole_callgraph.add_functions(chunk)
            total_added += len(chunk)
            # logger.info(f"Added {total_added} functions")

    def init_whole_callgraph(
        self, use_chunked_processing: bool = True, chunk_size: int = CHUNK_SIZE
    ) -> None:
        if self.whole_callgraph is None:
            self.whole_callgraph = self._get_whole_callgraph()

            if use_chunked_processing:
                self._add_all_functions_using_chunks(chunk_size)
            else:
                all_functions = self._get_all_functions()
                self.whole_callgraph.add_functions(all_functions)

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
