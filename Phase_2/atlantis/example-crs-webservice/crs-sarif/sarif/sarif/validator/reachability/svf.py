import multiprocessing as mp
from functools import partial
from pathlib import Path
from typing import Literal

from loguru import logger

from sarif.context import SarifCacheManager, SarifEnv
from sarif.models import CP, CodeLocation, Function, Harness
from sarif.utils.cache import cache_method_with_attrs
from sarif.validator.reachability.base import BaseReachabilityAnalyser
from sarif.validator.reachability.callgraph import CallGraph


def _create_callgraph_for_harness(
    harness: Harness, svf_dot_path: Path, mode: str, language: str
) -> tuple[str, CallGraph]:
    """Helper function to create CallGraph for a single harness (for multiprocessing)"""
    call_graph_dot_path = svf_dot_path / f"call_graph_{mode}_{harness.name}.dot"
    callgraph = CallGraph.from_svf_dot(
        call_graph_dot_path, language=language, harness=harness
    )
    return harness.name, callgraph


class SVFReachabilityAnalyser(BaseReachabilityAnalyser):
    SUPPORTED_MODES = Literal[
        "ander", "nander", "sander", "sfrander", "steens", "fspta", "vfspta", "type"
    ]
    name = "svf"
    max_workers = 4

    def __init__(
        self,
        cp: CP,
        *,
        mode: SUPPORTED_MODES | None = "ander",
        svf_dot_path: Path | None = None,
    ):
        super().__init__(cp)

        if self.cp.language != "c":
            raise ValueError("SVFReachabilityAnalyser only supports C")

        if svf_dot_path is None:
            svf_dot_path = SarifEnv().svf_dot_path

        self.mode = mode
        self.svf_dot_path = svf_dot_path

    @staticmethod
    def _check_reachable(
        reachable_functions: list[Function],
        sink_function: Function,
    ) -> bool:
        for reachable_function in reachable_functions:
            if reachable_function.func_name == sink_function.func_name:
                logger.info(
                    f"Reachable. Function {sink_function} can be reachable from harness"
                )
                return True
        else:
            logger.warning(
                f"Unreachable. Function {sink_function} cannot be reachable from harness"
            )
            return False

    def _get_whole_callgraph(self) -> CallGraph:
        logger.info("Creating merged call graph from multiple harnesses")

        # Filter harnesses that need callgraph creation
        harnesses_to_process = [
            harness
            for harness in self.cp.harnesses
            if harness.name not in self.callgraphs
        ]

        if harnesses_to_process:
            logger.info(
                f"Processing {len(harnesses_to_process)} harnesses in parallel with {self.max_workers} workers"
            )

            # Create partial function with fixed parameters
            create_callgraph_func = partial(
                _create_callgraph_for_harness,
                svf_dot_path=self.svf_dot_path,
                mode=self.mode,
                language=self.cp.language,
            )

            # Use multiprocessing to create callgraphs in parallel
            with mp.Pool(processes=self.max_workers) as pool:
                results = pool.map(create_callgraph_func, harnesses_to_process)

            # Store results in callgraphs dictionary
            for harness_name, callgraph in results:
                self.callgraphs[harness_name] = callgraph
                logger.debug(f"Created callgraph for harness: {harness_name}")

        merged_graph = CallGraph(language=self.cp.language)

        for harness in self.cp.harnesses:
            merged_graph.graph.add_nodes_from(
                self.callgraphs[harness.name].graph.nodes()
            )
            merged_graph.graph.add_edges_from(
                self.callgraphs[harness.name].graph.edges()
            )

        merged_graph.update_node_index()

        return merged_graph

    def init_whole_callgraph(self) -> None:
        if self.whole_callgraph is None:
            self.whole_callgraph = self._get_whole_callgraph()

    def reachability_analysis(
        self,
        sink_location: CodeLocation,
        harness: Harness | None = None,
    ) -> bool:
        reachable_harnesses = []
        if harness is None:
            for h in self.cp.harnesses:
                reachable_functions = self.get_all_reachable_funcs(h)
                status = self._check_reachable(
                    reachable_functions, sink_location.function
                )
                if status:
                    reachable_harnesses.append(h)
                logger.info(f"status: {status}")
        else:
            reachable_functions = self.get_all_reachable_funcs(harness)
            return self._check_reachable(reachable_functions, sink_location.function)

        logger.info(f"reachable_harnesses: {reachable_harnesses}")
