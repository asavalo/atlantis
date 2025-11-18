from pathlib import Path
from typing import Literal

from loguru import logger

from sarif.context import SarifCacheManager, SarifEnv
from sarif.models import CP, CodeLocation, Function, Harness
from sarif.utils.cache import cache_method_with_attrs
from sarif.validator.reachability.base import BaseReachabilityAnalyser
from sarif.validator.reachability.callgraph import CallGraph


class SVFReachabilityAnalyser(BaseReachabilityAnalyser):
    SUPPORTED_MODES = Literal[
        "ander", "nander", "sander", "sfrander", "steens", "fspta", "vfspta", "type"
    ]
    name = "svf"

    def __init__(
        self,
        cp: CP,
        *,
        mode: SUPPORTED_MODES | None = "ander",
        svf_dot_path: Path | None = None,
    ):
        super().__init__(cp)

        if svf_dot_path is None:
            svf_dot_path = SarifEnv().svf_dot_path

        self.mode = mode
        self.svf_dot_path = svf_dot_path
        if self.cp.language != "c":
            raise ValueError("SVFReachabilityAnalyser only supports C")

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

    # @cache_method_with_attrs(mem=SarifCacheManager().memory, attr_names=["cp", "mode"])
    def _get_whole_callgraph(self) -> CallGraph:
        logger.info("Creating merged call graph from multiple harnesses")

        for harness in self.cp.harnesses:
            logger.debug(f"harness: {harness}")
            if harness.name not in self.callgraphs:
                call_graph_dot_path = (
                    self.svf_dot_path / f"call_graph_{self.mode}_{harness.name}.dot"
                )
                self.callgraphs[harness.name] = CallGraph.from_svf_dot(
                    call_graph_dot_path, language=self.cp.language, harness=harness
                )

        merged_graph = CallGraph(language=self.cp.language)

        for harness in self.cp.harnesses:
            merged_graph.graph.add_nodes_from(
                self.callgraphs[harness.name].graph.nodes()
            )
            merged_graph.graph.add_edges_from(
                self.callgraphs[harness.name].graph.edges()
            )

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
