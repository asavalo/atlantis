import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Callable

import networkx as nx
from loguru import logger
from networkx.readwrite import json_graph
from pydantic_core import to_jsonable_python

from .models import Function, Harness, CallType, EdgeType


class CallGraph:
    C_ENTRYPOINT = "LLVMFuzzerTestOneInput"
    JAVA_ENTRYPOINT = "fuzzerTestOneInput"
    FUZZER_RELATED_FUNCTIONS = ["__sanitizer", "__asan", "asan.", "sancov.", "llvm."]

    def __init__(self, language: str = "c", harness: Harness | None = None):
        self.graph = nx.DiGraph()
        self.entrypoint: Function | None = None
        self.entrypoints: list[Function] = []
        self.language = language
        self.harness = harness

        self.node_index = {}
        self.node_index_cnt = 0

    def _find_node(self, function: Function) -> Function:
        for node in self.graph.nodes():
            if node == function:
                return node

        raise ValueError(f"Function {function} not found in call graph")

    def update_node_index(self) -> None:
        all_nodes: list[Function] = list(self.graph.nodes())
        if self.language in ["c", "cpp", "c++"]:
            # Use function name as key for c
            self.node_index: dict[str, list[Function]] = {}
            self.node_index_cnt = 0
            for node in all_nodes:
                if node.func_name not in self.node_index:
                    self.node_index[node.func_name] = []
                self.node_index[node.func_name].append(node)
                self.node_index_cnt += 1
        else:
            # Use class name and method descriptor as key for java
            self.node_index: dict[str, Function] = {}
            for node in all_nodes:
                self.node_index[
                    f"{node.class_name}:{node.func_name}:{node.method_desc}"
                ] = node

            self.node_index_cnt = len(self.node_index)

    def fast_node_search(self, function: Function) -> list[Function]:
        # node_count = self.graph.number_of_nodes()
        # if node_count != self.node_index_cnt:
        #     self.update_node_index()

        if self.language in ["c", "cpp", "c++"]:
            # match node by __eq__ function of Function
            try:
                matched_node = [
                    node
                    for node in self.node_index[function.func_name]
                    if node == function
                ]
            except KeyError:
                matched_node = []
        else:
            try:
                matched_node = [
                    self.node_index[
                        f"{function.class_name}:{function.func_name}:{function.method_desc}"
                    ]
                ]
            except KeyError:
                matched_node = []

        if len(matched_node) == 0:
            # logger.warning(f"Cannot find function {function} in call graph")
            return []
        # elif len(matched_node) > 1:
        #     logger.warning(f"Found multiple functions {function} in call graph")
        #     for node in matched_node:
        #         logger.warning(f"  {node}")

        return matched_node

    @classmethod
    def from_json(cls, json_file_path: Path, index_nodes: bool = True) -> "CallGraph":
        with open(json_file_path, "r") as f:
            data = json.load(f)

        if index_nodes:
            converted_graph: nx.DiGraph = json_graph.node_link_graph(data["graph"])
            mapping = {
                node_id: Function(**data["data"])
                for node_id, data in converted_graph.nodes(data=True)
            }
            graph = nx.relabel_nodes(converted_graph, mapping)
        else:
            graph = json_graph.node_link_graph(data["graph"])
        language = data["language"]
        harness = Harness(**data["harness"])
        entrypoint = Function(**data["entrypoint"]["data"])

        call_graph = cls(language, harness)
        call_graph.graph = graph
        call_graph.entrypoint = entrypoint

        return call_graph

    def to_json(self, index_nodes: bool = True):
        if self.harness == None and self.entrypoint == None:
            # Just dump reachable nodes from entrypoints in case of whole call graph
            # assert len(self.entrypoints) > 0

            dump_graph = self.subgraph(self.entrypoints).graph
        else:
            dump_graph = self.graph

        if index_nodes:
            converted_graph = nx.convert_node_labels_to_integers(
                dump_graph, label_attribute="data"
            )
        else:
            converted_graph = dump_graph

        if self.harness == None and self.entrypoint == None:
            # whole call graph
            # logger.info("Converting whole call graph.")
            indexed_entrypoint = []
            for entrypoint in self.entrypoints:
                indexed_entry = next(
                    (
                        {"id": node_id, "data": entrypoint}
                        for node_id, data in converted_graph.nodes(data=True)
                        if data["data"] == entrypoint
                    ),
                    None,
                )
                if indexed_entrypoint is None:
                    raise ValueError(f"Entrypoint {entrypoint} not found in call graph")

                indexed_entrypoint.append(indexed_entry)

        else:
            # per-harness call graph
            # logger.info(f"Converting {self.harness.name} call graph.")
            for node_id, data in converted_graph.nodes(data=True):
                if data["data"] == self.entrypoint:
                    indexed_entrypoint = {
                        "id": node_id,
                        "data": self.entrypoint,
                    }
                    break
            else:
                raise ValueError("Entrypoint not found in call graph")

        return to_jsonable_python(
            {
                "language": self.language,
                "harness": self.harness,
                "entrypoint": indexed_entrypoint,
                "graph": json_graph.node_link_data(converted_graph, edges="links"),
            }
        )

    def add_function(self, function: Function) -> None:
        self.graph.add_node(function)

    def add_functions(self, functions: list[Function]) -> None:
        self.graph.add_nodes_from(functions)

    def add_call(self, caller: Function, callee: Function, call_type: CallType) -> None:
        edge_attrs = {
            "call_type": call_type,
            "edge_type": EdgeType.from_call_type(call_type),
        }
        self.graph.add_edge(caller, callee, **edge_attrs)

    def set_entrypoint(self, function: Function) -> None:
        if function not in self.graph:
            self.add_function(function)
        self.entrypoint = function

    def get_entrypoint(self) -> Function | None:
        return self.entrypoint

    def get_callees(self, function: Function) -> set[Function]:
        return set(self.graph.successors(function))

    def get_callers(self, function: Function) -> set[Function]:
        return set(self.graph.predecessors(function))

    def get_all_functions(self) -> list[Function]:
        return list(self.graph.nodes())

    def has_path(self, start: Function, end: Function) -> bool:
        return nx.has_path(self.graph, start, end)

    def get_shortest_path(
        self, start: Function, end: Function
    ) -> list[Function] | None:
        try:
            return nx.shortest_path(self.graph, start, end)
        except nx.NetworkXNoPath:
            return None

    def get_strong_callgraph(self) -> "CallGraph":
        strong_edges = [
            (u, v)
            for u, v, data in self.graph.edges(data=True)
            if data["edge_type"] == EdgeType.STRONG
        ]
        strong_graph = nx.DiGraph()
        strong_graph.add_edges_from(strong_edges)

        return self.from_networkx(
            strong_graph, self.language, self.harness, self.entrypoint
        )

    def get_target_callgraph(
        self, target_func: Function, strong: bool = False
    ) -> "CallGraph":
        source_nodes = [self.entrypoint]
        sink_nodes = [self._find_node(target_func)]

        if strong:
            strong_graph = self.get_strong_callgraph()
            return strong_graph.subgraph(source_nodes, sink_nodes)
        else:
            return self.subgraph(source_nodes, sink_nodes)

    def get_all_paths(self, start: Function, end: Function) -> list[list[Function]]:
        # Too slow. Don't use it.
        return list(nx.all_simple_paths(self.graph, start, end))

    def is_empty(self) -> bool:
        return self.graph.number_of_nodes() == 0

    def clear(self) -> None:
        self.graph.clear()
        self.entrypoint = None

    @staticmethod
    def _parse_function_name(label: str) -> str:
        # Try different regex patterns to extract function name
        patterns = [
            r"fun:\s*([^\\}]+)",  # Match: fun: function_name
            r"fun:\s*([^\s|]+)",  # Match: fun: function_name with possible | afterward
            r"\\{fun:\s*([^\\}]+)",  # Match: \{fun: function_name
            r"\{fun:\s*([^}]+)\}",  # Match: {fun: function_name}
            r"fun:\s*(\w+[\w\._-]*)",  # Match: fun: with word characters, dots, underscores, hyphens
        ]

        for pattern in patterns:
            match = re.search(pattern, label)
            if match:
                result = match.group(1).strip()
                return result.split(".")[0]

        logger.warning(f"Failed to match any pattern for: {label}")
        return label

    def set_fuzzer_entrypoint(self) -> None:
        entrypoint_name = (
            self.C_ENTRYPOINT if self.language.lower() == "c" else self.JAVA_ENTRYPOINT
        )
        entrypoint_func = Function(
            func_name=entrypoint_name, file_name=self.harness.path.as_posix()
        )
        # logger.info(f"Entrypoint function: {entrypoint_func}")
        # Match the entrypoint function with just using func_name and file_name
        for node in self.graph.nodes():
            if (
                node.func_name == entrypoint_func.func_name
                and node.file_name == entrypoint_func.file_name
            ):
                entrypoint_func = node
                break
        else:
            raise ValueError(
                f"Fuzzer entrypoint function '{entrypoint_func}' not found in the call graph"
            )

        # if entrypoint_func not in self.graph:
        #     raise ValueError(
        #         f"Fuzzer entrypoint function '{entrypoint_func}' not found in the call graph"
        #     )

        self.set_entrypoint(entrypoint_func)

    def __filter_nodes(self, predicate: Callable[[Function], bool]) -> None:
        nodes_to_remove = [n for n in self.graph.nodes() if predicate(n)]

        self.graph.remove_nodes_from(nodes_to_remove)

        logger.debug(f"Filtered {len(nodes_to_remove)} nodes")

    def _filter_fuzzer_related_nodes(self) -> None:
        self.__filter_nodes(
            lambda node: node.func_name.startswith(
                tuple(self.FUZZER_RELATED_FUNCTIONS)
            ),
        )

        logger.debug("Fuzzer related nodes removed")

    def _remove_unreachable_nodes(self) -> None:
        if self.entrypoint is None:
            raise ValueError("Entrypoint not set")

        self.__filter_nodes(
            lambda node: not self.has_path(self.entrypoint, node),
        )

        logger.debug("Unreachable nodes removed")

    def _remove_nontarget_nodes(self) -> None:
        self.__filter_nodes(
            lambda node: node.file_name == "",
        )

    def is_reachable(self, end: Function) -> bool:
        if self.entrypoint is None:
            raise ValueError("Entrypoint not set")

        return self.has_path(self.entrypoint, end)

    def get_all_strong_reachable_funcs(self) -> list[Function]:
        try:
            strong_callgraph = self.get_strong_callgraph()
            return strong_callgraph.get_all_reachable_funcs()
        except Exception as e:
            logger.warning(f"Error getting all strong reachable functions: {e}")
            return []

    def get_all_reachable_funcs(self) -> list[Function]:
        if self.entrypoint is None:
            raise ValueError("Entrypoint not set")

        return list(nx.descendants(self.graph, self.entrypoint))

    def subgraph(
        self, source_nodes: list[Function], sink_nodes: list[Function] | None = None
    ) -> "CallGraph":
        forward_reachable_nodes = []

        forward_reachable_nodes.extend(source_nodes)
        for node in source_nodes:
            if node not in list(self.graph.nodes()):
                raise ValueError(f"Node {node} not found in graph")

            forward_reachable_nodes.extend(nx.descendants(self.graph, node))

        forward_reachable_nodes = list(set(forward_reachable_nodes))

        if sink_nodes is None:
            all_reachable_nodes = forward_reachable_nodes
        else:
            backward_reachable_nodes = []

            backward_reachable_nodes.extend(sink_nodes)
            for node in sink_nodes:
                if node not in list(self.graph.nodes()):
                    raise ValueError(f"Node {node} not found in graph")

                backward_reachable_nodes.extend(nx.ancestors(self.graph, node))

            # intersection of forward and backward reachable nodes
            all_reachable_nodes = list(
                set(forward_reachable_nodes) & set(backward_reachable_nodes)
            )

        subgraph = CallGraph.from_networkx(
            self.graph.subgraph(all_reachable_nodes).copy(),
            self.language,
            self.harness,
            self.entrypoint,
        )

        return subgraph

    def dump_dot(self, dot_file_path: Path, add_hash: bool = True) -> None:
        if add_hash:
            json_dict = self.to_json()
            json_str = json.dumps(json_dict)

            if self.language == "c":
                dot_file_path = dot_file_path.with_name(
                    f"{dot_file_path.stem}-{hashlib.md5(json_str.encode('utf-8')).hexdigest()}{dot_file_path.suffix}"
                )
            else:
                dot_file_path = dot_file_path.with_name(
                    f"{dot_file_path.stem}-{int(time.time())}-{hashlib.md5(json_str.encode('utf-8')).hexdigest()}{dot_file_path.suffix}"
                )
        nx.nx_agraph.write_dot(self.graph, dot_file_path.as_posix())

    def dump_json(
        self, json_file_path: Path, add_hash: bool = True, index_nodes: bool = True
    ) -> None:
        json_dict = self.to_json(index_nodes)

        if add_hash:
            json_str = json.dumps(json_dict)

            if self.language == "c":
                json_file_path = json_file_path.with_name(
                    f"{json_file_path.stem}-{hashlib.md5(json_str.encode('utf-8')).hexdigest()}{json_file_path.suffix}"
                )
            else:
                json_file_path = json_file_path.with_name(
                    f"{json_file_path.stem}-{int(time.time())}-{hashlib.md5(json_str.encode('utf-8')).hexdigest()}{json_file_path.suffix}"
                )

        with open(json_file_path, "w") as f:
            json.dump(json_dict, f)

    def print_stats(self) -> None:
        logger.info("Callgraph stats:")
        logger.info(f"  Nodes: {self.graph.number_of_nodes()}")
        logger.info(f"  Edges: {self.graph.number_of_edges()}")
        logger.info(f"  Entrypoint: {self.entrypoint}")

    # Factory methods
    @classmethod
    def from_networkx(
        cls,
        nx_graph: nx.DiGraph,
        language: str = "c",
        harness: Harness | None = None,
        entrypoint: Function | None = None,
    ) -> "CallGraph":
        call_graph = cls(language, harness)
        call_graph.graph = nx_graph

        if entrypoint is not None:
            call_graph.set_entrypoint(entrypoint)

        call_graph.update_node_index()

        return call_graph

    @classmethod
    def from_sootup_dot(
        cls, dot_file_path: Path, language: str = "java", harness: Harness | None = None
    ) -> "CallGraph":
        logger.warning("Do not use Sootup callgraph independently.")

        call_graph = cls(language, harness)
        call_graph.graph = nx.nx_agraph.read_dot(dot_file_path.as_posix())

        def _parse_sootup_label(label: str) -> tuple[str, str, str]:
            """
            Parse SootUp label format: <{class_name}: {function_full_signature}>
            Returns: (class_name, method_name, func_sig)
            """
            try:
                if label.startswith("<") and label.endswith(">"):
                    label = label[1:-1]

                if ": " not in label:
                    logger.warning(f"Invalid SootUp label format: {label}")
                    return "", label, ""

                class_name, func_sig = label.split(": ", 1)

                paren_index = func_sig.find("(")
                if paren_index == -1:
                    logger.warning(
                        f"No parentheses found in function signature: {func_sig}"
                    )
                    return class_name, func_sig, func_sig

                before_paren = func_sig[:paren_index].strip()

                parts = before_paren.split()
                if len(parts) < 1:
                    method_name = before_paren
                else:
                    method_name = parts[-1]

                return class_name, method_name, func_sig

            except Exception as e:
                logger.warning(f"Error parsing SootUp label '{label}': {e}")
                return "", label, ""

        def _get_function_info(node_id: str) -> tuple[str, str, str]:
            try:
                return _parse_sootup_label(node_id)
            except Exception as e:
                logger.warning(f"Error parsing SootUp node {node_id}: {e}")
                return "", str(node_id), ""

        call_graph.graph = nx.relabel_nodes(
            call_graph.graph,
            lambda x: Function(
                func_name=_get_function_info(x)[1],
                file_name="",  # No file_name information in DOT file
                class_name=_get_function_info(x)[0],
                method_desc="",  # No method_desc information in DOT file
                func_sig=_get_function_info(x)[2],  # Parsed function signature
            ),
        )

        # call_graph._remove_nontarget_nodes()
        # call_graph._filter_fuzzer_related_nodes()

        # if harness is not None:
        #     call_graph.set_fuzzer_entrypoint()
        #     # call_graph._remove_unreachable_nodes()

        call_graph.update_node_index()

        return call_graph

    @classmethod
    def from_svf_dot(
        cls, dot_file_path: Path, language: str = "c", harness: Harness | None = None
    ) -> "CallGraph":
        call_graph = cls(language, harness)
        original_graph = nx.nx_agraph.read_dot(dot_file_path.as_posix())

        original_nodes = list(original_graph.nodes(data=True))

        base_nodes = [node for node in original_nodes if ":" not in node[0]]

        call_graph.graph = nx.DiGraph()
        call_graph.graph.add_nodes_from(base_nodes)

        for u, v in original_graph.edges():
            u_base = u.split(":")[0] if ":" in u else u
            v_base = v.split(":")[0] if ":" in v else v
            call_graph.graph.add_edge(u_base, v_base)

        def _get_function_name(node_id):
            try:
                label = original_graph.nodes[node_id].get("label", node_id)
                return cls._parse_function_name(label)
            except Exception as e:
                logger.warning(f"Error parsing label for node {node_id}: {e}")
                return str(node_id)

        def _get_file_name(node_id):
            try:
                filename = original_graph.nodes[node_id].get("file_name", node_id)
                if "Node0x" in filename:
                    return ""
                # filename = filename.replace('"', "").split("/")[-1]
                filename = filename.replace('"', "")
                resolve_filename = os.path.normpath(filename)
                return resolve_filename

            except Exception as e:
                logger.warning(f"Error parsing file_name for node {node_id}: {e}")
                return str(node_id)

        call_graph.graph = nx.relabel_nodes(
            call_graph.graph,
            lambda x: Function(
                func_name=_get_function_name(x),
                file_name=_get_file_name(x),
            ),
        )

        call_graph._remove_nontarget_nodes()
        call_graph._filter_fuzzer_related_nodes()

        if harness is not None:
            call_graph.set_fuzzer_entrypoint()
            # call_graph._remove_unreachable_nodes()

        call_graph.update_node_index()

        return call_graph

    @staticmethod
    def _safe_parse_codeql_res(res: dict) -> dict:
        for key in res.keys():
            match key:
                case "from_func" | "to_func" | "from_file_abs" | "to_file_abs":
                    if res[key] == "UNKNOWN":
                        logger.warning(f"res: {res}")
                        raise ValueError(f"Missing required field: {key}")
                case "from_sig" | "to_sig" | "from_class" | "to_class":
                    if res[key] == "UNKNOWN":
                        res[key] = ""
                case (
                    "from_start_line"
                    | "to_start_line"
                    | "from_end_line"
                    | "to_end_line"
                ):
                    if res[key] == "UNKNOWN":
                        res[key] = -1
        return res

    @classmethod
    def from_codeql(
        cls, codeql_res: list[dict], language: str = "c", harness: Harness | None = None
    ) -> "CallGraph":
        call_graph = cls(language, harness)

        for res in codeql_res:
            try:
                res = CallGraph._safe_parse_codeql_res(res)
            except ValueError as e:
                logger.warning(f"Error parsing codeql result: {e}")
                continue

            from_sig = res["from_sig"] if "from_sig" in res else None
            to_sig = res["to_sig"] if "to_sig" in res else None
            from_class = res["from_class"] if "from_class" in res else None
            to_class = res["to_class"] if "to_class" in res else None
            from_method_desc = (
                res["from_method_desc"] if "from_method_desc" in res else None
            )
            to_method_desc = res["to_method_desc"] if "to_method_desc" in res else None
            is_direct = res["is_direct"] == "true" if "is_direct" in res else False

            caller = Function(
                func_name=res["from_func"],
                file_name=res["from_file_abs"],
                start_line=res["from_start_line"],
                end_line=res["from_end_line"],
                func_sig=from_sig,
                class_name=from_class,
                method_desc=from_method_desc,
            )
            callee = Function(
                func_name=res["to_func"],
                file_name=res["to_file_abs"],
                start_line=res["to_start_line"],
                end_line=res["to_end_line"],
                func_sig=to_sig,
                class_name=to_class,
                method_desc=to_method_desc,
            )

            if language == "c" or language == "cpp" or language == "c++":
                call_type = CallType.DIRECT if is_direct else CallType.INDIRECT
            elif language == "java" or language == "jvm":
                call_type = CallType.DIRECT if is_direct else CallType.POLYMORPHIC
            else:
                raise ValueError(f"Unsupported language: {language}")

            call_graph.add_call(caller, callee, call_type)

        if harness is not None:
            call_graph.set_fuzzer_entrypoint()

        call_graph.update_node_index()

        return call_graph

    def validate_nodes(self) -> None:
        if self.language == "c" or self.language == "cpp" or self.language == "c++":
            required_fields = [
                "func_name",
                "file_name",
                "func_sig",
                "start_line",
                "end_line",
            ]
        elif self.language == "java" or self.language == "jvm":
            required_fields = [
                "func_name",
                "file_name",
                "func_sig",
                "class_name",
                "method_desc",
            ]
        else:
            raise ValueError(f"Unsupported language: {self.language}")

        all_nodes: list[Function] = list(self.graph.nodes())

        for node in all_nodes:
            if "func_name" in required_fields and (
                node.func_name == "" or node.func_name is None
            ):
                logger.warning(f"Node {node} has empty func_name")
                raise ValueError(f"Node {node} has empty func_name")
            if "file_name" in required_fields and (
                node.file_name == "" or node.file_name is None
            ):
                logger.warning(f"Node {node} has empty file_name")
                raise ValueError(f"Node {node} has empty file_name")
            if "func_sig" in required_fields and (
                node.func_sig == "" or node.func_sig is None
            ):
                logger.warning(f"Node {node} has empty func_sig")
                raise ValueError(f"Node {node} has empty func_sig")
            if "start_line" in required_fields and (
                node.start_line == -1 or node.start_line is None
            ):
                logger.warning(f"Node {node} has empty start_line")
                raise ValueError(f"Node {node} has empty start_line")
            if "end_line" in required_fields and (
                node.end_line == -1 or node.end_line is None
            ):
                logger.warning(f"Node {node} has empty end_line")
                raise ValueError(f"Node {node} has empty end_line")
            if "class_name" in required_fields and (
                node.class_name == "" or node.class_name is None
            ):
                logger.warning(f"Node {node} has empty class_name")
                raise ValueError(f"Node {node} has empty class_name")
            if "method_desc" in required_fields and (
                node.method_desc == "" or node.method_desc is None
            ):
                logger.warning(f"Node {node} has empty method_desc")
                raise ValueError(f"Node {node} has empty method_desc")
