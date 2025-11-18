import json
from abc import ABC, abstractmethod
from typing import Literal

from loguru import logger

from sarif.context import SarifEnv
from sarif.models import (
    CP,
    CodeLocation,
    Function,
    FunctionCall,
    Harness,
    MethodInfo_Java,
    Relations_C,
    Relations_Java,
)
from sarif.validator.reachability.callgraph import CallGraph, CallType, EdgeType


class BaseReachabilityAnalyser(ABC):
    name = "base"
    SUPPORTED_MODES = Literal["mode"]

    def __init__(
        self,
        cp: CP,
    ):
        self.cp = cp
        self.whole_callgraph: CallGraph | None = None
        self.callgraphs: dict[str, CallGraph] = {}

    @staticmethod
    def _check_reachable(
        reachable_functions: list[Function],
        sink_function: Function,
        harness: Harness,
    ) -> bool:

        if sink_function in reachable_functions:
            logger.info(
                f"[{harness.name}] Reachable. Function {sink_function} can be reachable from harness"
            )
            return True
        else:
            logger.info(
                f"[{harness.name}] Unreachable. Function {sink_function} cannot be reachable from harness"
            )
            return False

    @abstractmethod
    def init_whole_callgraph(self) -> None: ...

    def init_callgraph(self) -> None:
        self.init_whole_callgraph()
        self.whole_callgraph.set_all_fuzzer_entrypoints()
        self.split_callgraph()

    def split_callgraph(self) -> None:
        for harness in self.cp.harnesses:
            all_nodes: list[Function] = [
                node for node in self.whole_callgraph.graph.nodes()
            ]
            harness_nodes = [
                node for node in all_nodes if node.file_name == harness.path.as_posix()
            ]

            self.callgraphs[harness.name] = self.whole_callgraph.subgraph(harness_nodes)
            self.callgraphs[harness.name].harness = harness
            self.callgraphs[harness.name].set_fuzzer_entrypoint()

    def get_callgraph(self, harness: Harness | None = None) -> CallGraph:
        if self.whole_callgraph is None:
            self.init_callgraph()

        if harness is None:
            return self.whole_callgraph
        else:
            return self.callgraphs[harness.name]

    def get_target_callgraph(
        self, sink_location: CodeLocation, harness: Harness | None = None
    ) -> CallGraph:
        callgraph = self.get_callgraph(harness)

        return callgraph.get_target_callgraph(sink_location.function)

    @staticmethod
    def _java_method_info_to_function(method: MethodInfo_Java) -> Function | None:
        class_blacklists = ["ch.qos.logback"]

        if method.method_name == "<init>":
            method.method_name = method.class_name.split(".")[-1]

        if "$" in method.method_name:
            method.method_name = method.method_name.split("$")[-1]

        for blacklist in class_blacklists:
            if method.class_name.startswith(blacklist):
                return None

        return Function(
            file_name=method.file,
            func_name=method.method_name,
            class_name=method.class_name,
            method_desc=method.prototype,
            start_line=-1,
            end_line=-1,
        )

    def _relations_to_function_calls(
        self, relations: Relations_C | Relations_Java
    ) -> list[FunctionCall]:
        function_calls: set[FunctionCall] = set()
        if self.cp.language == "c" or self.cp.language == "cpp":
            for relation in relations:
                caller = Function(
                    file_name=relation.caller.file,
                    func_name=relation.caller.function_name,
                )
                for callstate in relation.callees:
                    callee = Function(
                        file_name=callstate.callee.file,
                        func_name=callstate.callee.function_name,
                    )
                    function_calls.add(FunctionCall(caller=caller, callee=callee))
        elif self.cp.language == "java" or self.cp.language == "jvm":
            for relation in relations:
                caller = self._java_method_info_to_function(relation.caller)
                if caller is None:
                    continue

                for callstate in relation.callees:
                    callee = self._java_method_info_to_function(callstate.callee)
                    if callee is None:
                        continue

                    function_calls.add(FunctionCall(caller=caller, callee=callee))

        return list(function_calls)

    def update_callgraph_batch(
        self, batch_relations: list[Relations_C | Relations_Java]
    ) -> int:
        function_call_set: set[FunctionCall] = set()

        for relations in batch_relations:
            function_call_set.update(self._relations_to_function_calls(relations))

        updated_edges = self.update_callgraph(list(function_call_set))

        return updated_edges

    def update_callgraph(self, function_calls: list[FunctionCall]) -> int:
        edges = [(call.caller, call.callee) for call in function_calls]

        # new_edges = [
        #     edge for edge in edges if edge not in self.whole_callgraph.graph.edges()
        # ]
        new_edges = [
            edge for edge in edges if not self.whole_callgraph.graph.has_edge(*edge)
        ]

        # for edge in new_edges:
        #     caller = edge[0]
        #     callee = edge[1]

        #     all_nodes = self.whole_callgraph.graph.nodes()

        #     # Debugging newly found nodes
        #     if caller not in all_nodes:
        #         logger.warning(f"Caller {caller} not in all_nodes. Adding it...")

        #     if callee not in all_nodes:
        #         logger.warning(f"Callee {callee} not in all_nodes. Adding it...")

        logger.info(f"Updating callgraph with {len(new_edges)} new edges")

        if len(new_edges) > 0:
            edge_attrs = {
                "call_type": CallType.DYNAMIC,
                "edge_type": EdgeType.from_call_type(CallType.DYNAMIC),
            }

            self.whole_callgraph.graph.add_edges_from(tuple(new_edges), **edge_attrs)
            self.split_callgraph()

        return len(new_edges)

    def get_all_reachable_funcs(self, harness: Harness | None = None) -> list[Function]:
        return self.get_callgraph(harness).get_all_reachable_funcs()

    def _save_reachable_funcs(self, harness: Harness) -> None:
        reachable_funcs = self.get_all_reachable_funcs(harness)
        with open(
            SarifEnv().reachability_shared_dir / f"{harness.name}.json", "w"
        ) as f:
            reachable_funcs_json = [func.model_dump() for func in reachable_funcs]
            json.dump(reachable_funcs_json, f)

    def dump_all_callgraphs(self, format: Literal["dot", "json"] = "dot") -> None:
        self.dump_callgraph(format=format)
        for harness in self.cp.harnesses:
            self.dump_callgraph(harness, format=format)

    def dump_callgraph(
        self, harness: Harness | None = None, format: Literal["dot", "json"] = "dot"
    ) -> None:
        callgraph = self.get_callgraph(harness)
        harness_name = harness.name if harness is not None else "whole"
        if format == "dot":
            callgraph.dump_dot(
                SarifEnv().reachability_shared_dir / f"{harness_name}.dot"
            )
        elif format == "json":
            callgraph.dump_json(
                SarifEnv().reachability_shared_dir / f"{harness_name}.json"
            )

    def save_all_reachable_funcs(self) -> None:
        for harness in self.cp.harnesses:
            self._save_reachable_funcs(harness)

    def reachability_analysis(
        self,
        sink_location: CodeLocation,
        harness: Harness | None = None,
        *,
        mode: SUPPORTED_MODES = "mode",
    ) -> bool:
        reachable_functions = self.get_all_reachable_funcs(harness)

        return self._check_reachable(
            reachable_functions, sink_location.function, harness
        )

    def get_reachable_harnesses(self, sink_location: CodeLocation) -> list[Harness]:
        reachable_harnesses = []

        for harness in self.cp.harnesses:
            reachable_functions = self.get_all_reachable_funcs(harness)
            if self._check_reachable(
                reachable_functions, sink_location.function, harness
            ):
                reachable_harnesses.append(harness)

        return reachable_harnesses

    def get_callpath(
        self, sink_location: CodeLocation, harness: Harness
    ) -> list[Function]:
        # TODO: add priority to the callpath
        callgraph = self.get_callgraph(harness)

        shortest_path = callgraph.get_shortest_path(
            callgraph.get_entrypoint(),
            sink_location.function,
        )

        if shortest_path is None:
            raise ValueError(
                f"No callpath found from harness {harness.name} to {sink_location.function.func_name}"
            )

        return shortest_path
