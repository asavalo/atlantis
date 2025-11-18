import json
import os
import subprocess
from abc import ABC, abstractmethod
from importlib.resources import files
from pathlib import Path
from typing import Literal

import jpype
import jpype.imports
from loguru import logger

from sarif.context import SarifCacheManager, SarifEnv
from sarif.models import CP, CodeLocation, Function, FunctionCoverage, SarifInfo
from sarif.utils.cache import cache_method_with_attrs
from sarif.validator.reachability.base import (
    BaseReachabilityAnalyser,
    CallGraphGenerationError,
)
from sarif.validator.reachability.callgraph import CallGraph


class SootupReachabilityAnalyser(BaseReachabilityAnalyser):
    SUPPORTED_MODES = Literal["cha", "rta", "pta"]
    SUPPORTED_PTA_ALGORITHMS = Literal[
        "insens",
        "callsite_sensitive_1",
        "callsite_sensitive_2",
        "object_sensitive_1",
        "object_sensitive_2",
        "type_sensitive_1",
        "type_sensitive_2",
        "hybrid_object_sensitive_1",
        "hybrid_object_sensitive_2",
        "hybrid_type_sensitive_1",
        "hybrid_type_sensitive_2",
        "eagle_object_sensitive_1",
        "eagle_object_sensitive_2",
        "zipper_object_sensitive_1",
        "zipper_object_sensitive_2",
        "zipper_callsite_sensitive_1",
        "zipper_callsite_sensitive_2",
    ]
    name = "sootup"

    @staticmethod
    def _parse_class_paths(
        cpmeta_dict: dict,
        cp_built_path: Path | None = None,
        cp_src_path: Path | None = None,
    ) -> list[str]:
        harness: dict = cpmeta_dict["harnesses"]

        built_path: str = cpmeta_dict["built_path"]
        src_path: str = cpmeta_dict["cp_full_src"]

        all_classpaths = set()
        for _name, value in harness.items():
            classpath = value["classpath"]
            all_classpaths.update(classpath)

        converted_paths = set()
        for path in all_classpaths:
            if built_path in path:
                converted_paths.add(
                    path.replace(
                        built_path, str(cp_built_path) if cp_built_path else "/out"
                    )
                )
            elif src_path in path:
                converted_paths.add(
                    path.replace(src_path, str(cp_src_path) if cp_src_path else "/src")
                )
            elif path.endswith(".xml"):
                continue
            else:
                converted_paths.add(path)

        return list(converted_paths)

    def _setup_cpmeta_from_env(self) -> None:
        self.cpmeta_paths = SarifEnv().cpmeta_paths
        if SarifEnv().cpmeta_dicts is None:
            self.cpmeta_dicts = [
                json.load(open(cpmeta_path)) for cpmeta_path in self.cpmeta_paths
            ]
        else:
            self.cpmeta_dicts = SarifEnv().cpmeta_dicts

        class_paths_set = set()
        for cpmeta_dict in self.cpmeta_dicts:
            class_paths_set.update(
                self._parse_class_paths(
                    cpmeta_dict,
                    cp_built_path=self.cp_built_path,
                    cp_src_path=self.cp_src_path,
                )
            )
        self.class_paths = list(class_paths_set)

    def __init__(
        self,
        cp: CP,
        *,
        mode: SUPPORTED_MODES | None = None,
        pta_algorithm: SUPPORTED_PTA_ALGORITHMS | None = None,
        sootup_dot_path: Path | None = None,
        cpmeta_paths: list[Path] | None = None,
        cp_built_path: Path | None = None,
        cp_src_path: Path | None = None,
    ):
        super().__init__(cp)

        if self.cp.language != "java":
            raise ValueError("SootupReachabilityAnalyser only supports Java")

        if sootup_dot_path is None:
            sootup_dot_path = SarifEnv().sootup_dot_path

        self.cp_built_path = cp_built_path
        self.cp_src_path = cp_src_path

        if cpmeta_paths is None:
            try:
                self._setup_cpmeta_from_env()
            except TypeError:
                logger.warning(
                    "CPMeta is not set yet. Please set it before running sootup tool."
                )

        else:
            self.cpmeta_paths = cpmeta_paths
            self.cpmeta_dicts = [
                json.load(open(cpmeta_path)) for cpmeta_path in self.cpmeta_paths
            ]
            class_paths_set = set()
            for cpmeta_dict in self.cpmeta_dicts:
                class_paths_set.update(
                    self._parse_class_paths(
                        cpmeta_dict,
                        cp_built_path=self.cp_built_path,
                        cp_src_path=self.cp_src_path,
                    )
                )
            self.class_paths = list(class_paths_set)

        self.sootup_dot_path = sootup_dot_path

        if mode is None:
            self.mode = "cha"
        else:
            self.mode = mode

        if pta_algorithm is None:
            self.pta_algorithm = "insens"
        else:
            self.pta_algorithm = pta_algorithm

        self.jar_path = Path(files("sarif.static") / "sootup-reachability.jar")

        if not self.jar_path.exists():
            raise FileNotFoundError(f"JAR file not found at {self.jar_path}")

        self.jre_path = Path(files("sarif.static") / "jre1.6.0_45")

    def _generate_whole_callgraph(self) -> None:
        cmd = [
            # "java",
            "/usr/lib/jvm/java-17-openjdk-amd64/bin/java",
            "-jar",
            self.jar_path.as_posix(),
            "generate-call-graph",
            ":".join(self.class_paths),
            "--cg-method",
            self.mode,
            "--pta-algorithm",
            self.pta_algorithm,
            "--output",
            (self.sootup_dot_path / "callgraph_sootup.dot").as_posix(),
        ]

        logger.info(f"Sootup command: {cmd}")

        subprocess.run(cmd, shell=False)

        self.call_graph_dot_files = list(self.sootup_dot_path.glob("*.dot"))

        if len(self.call_graph_dot_files) == 0:
            logger.error("Call graph generation failed. Do not use Sootup.")
            raise CallGraphGenerationError(
                "Call graph generation failed. Do not use Sootup."
            )

    def _get_whole_callgraph(self) -> CallGraph:
        self._generate_whole_callgraph()

        for dot_file in self.call_graph_dot_files:
            logger.debug(f"dot_file: {dot_file}")
            if dot_file.name not in self.callgraphs:
                self.callgraphs[dot_file.name] = CallGraph.from_sootup_dot(
                    Path(dot_file), language=self.cp.language
                )

        merged_graph = CallGraph(language=self.cp.language)

        for dot_file in self.call_graph_dot_files:
            merged_graph.graph.add_nodes_from(
                self.callgraphs[dot_file.name].graph.nodes()
            )
            merged_graph.graph.add_edges_from(
                self.callgraphs[dot_file.name].graph.edges()
            )

        merged_graph.update_node_index()

        return merged_graph

    def init_whole_callgraph(self) -> None:
        if self.whole_callgraph is None:
            self.whole_callgraph = self._get_whole_callgraph()

    def _get_all_fuzzer_entrypoints(self) -> None:
        entrypoint_name = "fuzzerTestOneInput"
        entrypoints = []
        for node in self.whole_callgraph.graph.nodes():
            if node.func_name == entrypoint_name:
                entrypoints.append(node)

        return entrypoints

    def init_callgraph(self) -> None:
        if self.cpmeta_paths is None or len(self.cpmeta_paths) == 0:
            self._setup_cpmeta_from_env()

        self.init_whole_callgraph()
        self.whole_callgraph.entrypoints = self._get_all_fuzzer_entrypoints()
