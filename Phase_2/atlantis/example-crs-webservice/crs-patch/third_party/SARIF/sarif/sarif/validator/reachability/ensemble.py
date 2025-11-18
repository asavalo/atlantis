from statistics import mode as common_value
from typing import Literal

from loguru import logger

from sarif.context import SarifCacheManager, SarifEnv
from sarif.models import CP, CodeLocation, Function, LanguageReachabilityConfig
from sarif.utils.cache import cache_method_with_attrs
from sarif.validator.reachability.base import BaseReachabilityAnalyser
from sarif.validator.reachability.codeql import CodeQLReachabilityAnalyser
from sarif.validator.reachability.introspector import IntrospectorReachabilityAnalyser
from sarif.validator.reachability.joern import JoernReachabilityAnalyser
from sarif.validator.reachability.sootup import SootupReachabilityAnalyser
from sarif.validator.reachability.svf import SVFReachabilityAnalyser


class EnsembleReachabilityAnalyser(BaseReachabilityAnalyser):
    SUPPORTED_TOOLS = {
        "c": ["codeql", "joern", "introspector", "SVF"],
        "cpp": ["codeql", "joern", "introspector", "SVF"],
        # "java": ["codeql", "joern", "introspector", "sootup"],
        "java": ["codeql", "joern", "sootup"],
    }

    def __init__(
        self,
        cp: CP,
        *,
        policy: LanguageReachabilityConfig,
    ):
        self.cp = cp

        tool_names = [tool.name for tool in policy.tool_list]

        if not all(
            tool in self.SUPPORTED_TOOLS[self.cp.language] for tool in tool_names
        ):
            raise ValueError(
                f"Unsupported tools for language {self.cp.language}: {tool_names}"
            )

        self.policy = policy

    def _get_analyser(self, tool: str) -> BaseReachabilityAnalyser:
        if tool == "codeql":
            return CodeQLReachabilityAnalyser(
                self.cp, db_path=SarifEnv().codeql_db_path
            )
        elif tool == "joern":
            return JoernReachabilityAnalyser(
                self.cp, cpg_path=SarifEnv().joern_cpg_path
            )
        elif tool == "introspector":
            return IntrospectorReachabilityAnalyser(self.cp)
        elif tool == "SVF":
            return SVFReachabilityAnalyser(self.cp)
        elif tool == "sootup":
            return SootupReachabilityAnalyser(self.cp)
        else:
            raise ValueError(f"Unsupported tool: {tool}")

    @cache_method_with_attrs(
        mem=SarifCacheManager().memory, attr_names=["cp", "tool_list"]
    )
    def get_all_reachable_funcs(self) -> list[Function]:
        ensmebled_reachable_functions: set[Function] = set()

        for tool in self.tool_list:
            logger.info(f"Running {tool} reachability analysis")
            analyser = self._get_analyser(tool)
            reachable_functions = analyser.get_all_reachable_funcs()

            ensmebled_reachable_functions.update(reachable_functions)

        return ensmebled_reachable_functions

    def reachability_analysis(
        self,
        sink_location: CodeLocation,
        *,
        mode: Literal["Any", "All", "Voting"] | None = None,
    ) -> bool:
        # reachable_functions = self.get_all_reachable_funcs()

        # return self._check_reachable(reachable_functions, sink_location.function)

        if mode is None:
            mode = self.policy.policy

        results = []
        for tool in self.policy.tool_list:
            logger.info(f"Running {tool} reachability analysis")
            analyser = self._get_analyser(tool)
            res = analyser.reachability_analysis(sink_location, **tool.options)
            if mode == "Any" and res == True:
                return True
            elif mode == "All" and res == False:
                return False
            elif mode == "Voting":
                results.append(res)

        match mode:
            case "Any":
                return False
            case "All":
                return True
            case "Voting":
                return common_value(results)

        return False
