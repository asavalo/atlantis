import os
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
from sarif.validator.reachability.base import BaseReachabilityAnalyser


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

    def __init__(
        self,
        cp: CP,
        *,
        mode: SUPPORTED_MODES | None = "cha",
        pta_algorithm: SUPPORTED_PTA_ALGORITHMS | None = "insens",
        dump_call_graph: bool = False,
        output_dir: str | None = None,
    ):
        self.cp = cp
        self.mode = mode
        self.pta_algorithm = pta_algorithm
        self.dump_call_graph = dump_call_graph
        self.output_dir = output_dir

        if self.cp.language != "java":
            raise ValueError("SootupReachabilityAnalyser only supports Java")

        self.jar_path = Path(files("sarif.static") / "sootup-reachability.jar")

        if not self.jar_path.exists():
            raise FileNotFoundError(f"JAR file not found at {self.jar_path}")

        self.jre_path = Path(files("sarif.static") / "jre1.6.0_45")

    @cache_method_with_attrs(
        mem=SarifCacheManager().memory, attr_names=["cp", "mode", "pta_algorithm"]
    )
    def get_all_reachable_funcs(self) -> list[Function]:
        if not jpype.isJVMStarted():
            jpype.startJVM(
                "-Xmx" + os.getenv("JAVA_XMX", "12g"),
                "-Xms" + os.getenv("JAVA_XMS", "4g"),
                classpath=str(self.jar_path),
            )

        try:
            # Import the Java classes
            String = jpype.JClass("java.lang.String")
            SootupReachabilityAnalyserJava = jpype.JClass(
                "sarif.SootupReachabilityAnalyser"
            )
            CGMethod = jpype.JClass("sarif.CGMethod")
            PTAAlgorithm = jpype.JClass("sarif.PTAAlgorithm")

            # Create Java String objects
            input_dir = String(str(SarifEnv().class_dir))

            # Get enum values
            cg_method = CGMethod.valueOf(self.mode.upper())
            pta_algorithm = PTAAlgorithm.valueOf(self.pta_algorithm.upper())
            jre_path = String(self.jre_path.as_posix())

            # Create instance with required parameters
            analyser = SootupReachabilityAnalyserJava(
                input_dir,
                cg_method,
                pta_algorithm,
                jre_path,
                self.dump_call_graph,
                self.output_dir,
            )

            # Get all reachable methods
            reachable_methods = analyser.getAllReachableMethods()

            # Convert Java methods to Function objects
            functions = []
            for method in reachable_methods:
                method_name = str(method.getName())
                class_name = str(method.getDeclClassType().toString())
                # TODO: SKIP??
                # if class_name.startswith("java.") or class_name.startswith("javax."):
                #     continue
                # TODO: get accurate file name
                file_name = class_name.split(".")[-1] + ".java"

                function = Function(file_name=file_name, func_name=method_name)
                functions.append(function)

            if jpype.isJVMStarted():
                jpype.shutdownJVM()

            return functions

        except Exception as e:
            logger.error(f"Error running SootupReachabilityAnalyser: {str(e)}")
            raise

    def reachability_analysis(
        self,
        sink_location: CodeLocation,
        *,
        mode: SUPPORTED_MODES | None = None,
    ) -> bool:
        reachable_functions = self.get_all_reachable_funcs()

        return self._check_reachable(reachable_functions, sink_location.function)
