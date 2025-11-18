import concurrent.futures
import json
import os
import threading
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from typing import Literal

from loguru import logger

from sarif.context import SarifEnv
from sarif.models import (
    CP,
    CodeLocation,
    ConfidenceLevel,
    Function,
    FunctionCall,
    Harness,
    MethodInfo_Java,
    Relation_C,
    Relation_Java,
    Relations_C,
    Relations_Java,
)
from sarif.validator.reachability.callgraph import CallGraph, CallType, EdgeType


class CallGraphGenerationError(Exception):
    pass


class BaseReachabilityAnalyser(ABC):
    name = "base"
    SUPPORTED_MODES = Literal["mode"]

    MIN_BATCH_SIZE_FOR_PARALLEL = 10
    MAX_BATCH_WORKERS = 10
    PROGRESS_LOG_INTERVAL = 50

    def __init__(
        self,
        cp: CP,
    ):
        self.cp = cp
        self.whole_callgraph: CallGraph | None = None
        self.callgraphs: dict[str, CallGraph] = {}
        self._thread_pool: ThreadPoolExecutor | None = None
        self._thread_pool_lock = threading.Lock()

    def __del__(self):
        if self._thread_pool:
            self._thread_pool.shutdown(wait=True)

    def _get_thread_pool(self, max_workers: int) -> ThreadPoolExecutor:
        with self._thread_pool_lock:
            if (
                self._thread_pool is None
                or self._thread_pool._max_workers != max_workers
            ):
                if self._thread_pool:
                    self._thread_pool.shutdown(wait=False)
                self._thread_pool = ThreadPoolExecutor(max_workers=max_workers)
            return self._thread_pool

    @staticmethod
    def _check_reachable(
        reachable_functions: list[Function],
        sink_function: Function,
        harness: Harness,
        strong: bool = False,
    ) -> bool:

        if sink_function in reachable_functions:
            logger.info(
                f"[{harness.name}] [{'Strong' if strong else 'Weak'}] Reachable. Function {sink_function} can be reachable from harness"
            )
            return True
        else:
            logger.info(
                f"[{harness.name}] [{'Strong' if strong else 'Weak'}] Unreachable. Function {sink_function} cannot be reachable from harness"
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
        self,
        sink_location: CodeLocation,
        harness: Harness | None = None,
        strong: bool = False,
    ) -> CallGraph:
        callgraph = self.get_callgraph(harness)

        return callgraph.get_target_callgraph(sink_location.function, strong=strong)

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
            file_name=os.path.normpath(method.file),
            func_name=method.method_name,
            class_name=method.class_name,
            method_desc=method.prototype,
            start_line=-1,
            end_line=-1,
        )

    def _function_calls_to_nodes(
        self, function_calls: list[FunctionCall]
    ) -> list[FunctionCall]:
        node_calls_set: set[FunctionCall] = set()
        unfound_node_count = 0
        logger.info(f"All function calls: {len(function_calls)}")

        for function_call in function_calls:
            caller_nodes = self.whole_callgraph.fast_node_search(function_call.caller)
            callee_nodes = self.whole_callgraph.fast_node_search(function_call.callee)

            # if len(caller_nodes) == 0:
            #     logger.warning(f"Caller {function_call.caller} not found in callgraph")
            # if len(callee_nodes) == 0:
            #     logger.warning(f"Callee {function_call.callee} not found in callgraph")

            if len(caller_nodes) > 0 and len(callee_nodes) > 0:
                from itertools import product

                node_calls_set.update(
                    FunctionCall(caller=caller, callee=callee)
                    for caller, callee in product(caller_nodes, callee_nodes)
                )
            else:
                unfound_node_count += 1

        logger.info(f"All node calls: {len(node_calls_set)}")
        logger.info(f"Unfound node count: {unfound_node_count}")

        return list(node_calls_set)

    def _relations_to_function_calls(
        self, relations: Relations_C | Relations_Java
    ) -> list[FunctionCall]:
        function_calls: set[FunctionCall] = set()

        if self.cp.language == "c" or self.cp.language == "cpp":
            for relation in relations:
                function_calls.update(self._process_single_c_relation(relation))

        elif self.cp.language == "java" or self.cp.language == "jvm":
            for relation in relations:
                function_calls.update(self._process_single_java_relation(relation))

        return list(function_calls)

    def _process_single_c_relation(self, relation: Relation_C) -> set[FunctionCall]:
        caller_function = Function(
            file_name=os.path.normpath(relation.caller.file),
            func_name=relation.caller.function_name,
            class_name=(
                relation.harness_name
                if relation.caller.function_name == "LLVMFuzzerTestOneInput"
                else None
            ),
        )

        calle_functions = []
        for callstate in relation.callees:
            callee_function = Function(
                file_name=os.path.normpath(callstate.callee.file),
                func_name=callstate.callee.function_name,
                class_name=(
                    relation.harness_name
                    if callstate.callee.function_name == "LLVMFuzzerTestOneInput"
                    else None
                ),
            )
            calle_functions.append(callee_function)

        return {
            FunctionCall(caller=caller_function, callee=callee)
            for callee in calle_functions
        }

    def _process_single_java_relation(
        self, relation: Relation_Java
    ) -> set[FunctionCall]:
        caller_function = self._java_method_info_to_function(relation.caller)
        if caller_function is None:
            return set()

        calle_functions = []
        for callstate in relation.callees:
            callee_function = self._java_method_info_to_function(callstate.callee)
            if callee_function is not None:
                calle_functions.append(callee_function)

        return {
            FunctionCall(caller=caller_function, callee=callee)
            for callee in calle_functions
        }

    def update_callgraph_batch(
        self,
        batch_relations: list[Relations_C | Relations_Java],
    ) -> int:
        start_time = time.time()
        function_call_set: set[FunctionCall] = set()

        logger.info(f"Processing {len(batch_relations)} batch relations...")

        if len(batch_relations) < self.MIN_BATCH_SIZE_FOR_PARALLEL:
            logger.info("Using sequential processing for small batch")
            for relations in batch_relations:
                function_call_set.update(self._relations_to_function_calls(relations))
        else:
            max_workers = min(len(batch_relations), self.MAX_BATCH_WORKERS)
            logger.info(f"Using parallel processing with {max_workers} workers")
            thread_pool = self._get_thread_pool(max_workers)

            futures = [
                thread_pool.submit(self._relations_to_function_calls, relations)
                for relations in batch_relations
            ]

            completed_count = 0
            for future in concurrent.futures.as_completed(futures):
                try:
                    function_calls = future.result()
                    function_call_set.update(function_calls)
                    completed_count += 1

                    if completed_count % self.PROGRESS_LOG_INTERVAL == 0:
                        logger.info(
                            f"Completed {completed_count}/{len(batch_relations)} relations"
                        )
                except Exception as exc:
                    logger.exception(f"Error processing relations: {exc}")

        processing_time = time.time() - start_time
        logger.info(f"Batch processing completed in {processing_time:.2f} seconds")
        logger.info(f"Generated {len(function_call_set)} unique function calls")

        node_calls = self._function_calls_to_nodes(list(function_call_set))

        updated_edges = self.update_callgraph(node_calls)

        total_time = time.time() - start_time
        logger.info(f"Total update_callgraph_batch time: {total_time:.2f} seconds")

        return updated_edges

    def update_callgraph(self, function_calls: list[FunctionCall]) -> int:
        edges = [(call.caller, call.callee) for call in function_calls]
        edge_attrs = {
            "call_type": CallType.DYNAMIC,
            "edge_type": EdgeType.from_call_type(CallType.DYNAMIC),
        }

        new_edges = []
        num_call_type_changes = 0

        for edge in edges:
            if self.whole_callgraph.graph.has_edge(*edge):
                edge_label = self.whole_callgraph.graph.get_edge_data(*edge)[
                    "call_type"
                ]
                if edge_label != CallType.DYNAMIC:
                    self.whole_callgraph.graph.add_edge(*edge, **edge_attrs)
                    num_call_type_changes += 1
            else:
                new_edges.append(edge)

        logger.info(f"Updating callgraph with {len(new_edges)} new edges")
        logger.info(f"Number of call type changes: {num_call_type_changes}")

        if len(new_edges) > 0:
            self.whole_callgraph.graph.add_edges_from(tuple(new_edges), **edge_attrs)
            self.whole_callgraph.update_node_index()

        if len(new_edges) > 0 or num_call_type_changes > 0:
            self.split_callgraph()

        return len(new_edges)

    def get_all_strong_reachable_funcs(
        self, harness: Harness | None = None
    ) -> list[Function]:
        return self.get_callgraph(harness).get_all_strong_reachable_funcs()

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
        import concurrent.futures

        dump_tasks = [(None, format)]
        dump_tasks.extend([(harness, format) for harness in self.cp.harnesses])

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(dump_tasks), 8)
        ) as executor:
            futures = [
                executor.submit(self.dump_callgraph, harness, fmt)
                for harness, fmt in dump_tasks
            ]

            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.exception(f"Error dumping callgraph: {e}")

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
        strong: bool = False,
    ) -> bool:
        reachable_functions = self.get_all_reachable_funcs(harness)

        return self._check_reachable(
            reachable_functions, sink_location.function, harness, strong=strong
        )

    def get_reachable_harnesses(
        self, sink_location: CodeLocation
    ) -> list[tuple[Harness, ConfidenceLevel]]:
        reachable_harnesses = []

        for harness in self.cp.harnesses:
            # Check strong reachability
            reachable_functions = self.get_all_strong_reachable_funcs(harness)
            if self._check_reachable(
                reachable_functions, sink_location.function, harness, strong=True
            ):
                reachable_harnesses.append((harness, ConfidenceLevel.HIGH))
                continue

            # Check weak reachability
            reachable_functions = self.get_all_reachable_funcs(harness)
            if self._check_reachable(
                reachable_functions, sink_location.function, harness, strong=False
            ):
                reachable_harnesses.append((harness, ConfidenceLevel.LOW))
                continue

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
