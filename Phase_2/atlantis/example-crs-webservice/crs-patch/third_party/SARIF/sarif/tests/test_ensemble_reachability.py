import pytest
from loguru import logger

from sarif.context import init_context
from sarif.models import CP, CodeLocation
from sarif.validator.reachability.ensemble import EnsembleReachabilityAnalyser


class TestEnsembleReachability:

    @pytest.mark.parametrize(
        "tool_list",
        [
            # ["codeql"],
            ["codeql", "introspector"],
            # ["codeql", "joern", "introspector"],
        ],
    )
    def test_ensemble_reachability_asc_nginx_tp(
        self,
        cp: CP,
        tp_sink_location: CodeLocation,
        tool_list: list[str],
    ):
        init_context(cp, env_mode="local", debug_mode="debug")
        analyser = EnsembleReachabilityAnalyser(cp, tool_list=tool_list)
        res = analyser.reachability_analysis(tp_sink_location)
        logger.info(f"Reachability analysis result: {res}")

    @pytest.mark.parametrize(
        "tool_list",
        [
            # ["codeql"],
            ["codeql", "introspector"],
            # ["codeql", "joern", "introspector"],
        ],
    )
    def test_ensemble_reachability_asc_nginx_fp(
        self,
        cp: CP,
        fp_sink_location: CodeLocation,
        tool_list: list[str],
    ):
        init_context(cp, env_mode="local", debug_mode="debug")
        analyser = EnsembleReachabilityAnalyser(cp, tool_list=tool_list)
        res = analyser.reachability_analysis(fp_sink_location)
        logger.info(f"Reachability analysis result: {res}")

    @pytest.mark.parametrize(
        "tool_list",
        [
            # ["codeql"],
            ["codeql", "sootup"],
            # ["codeql", "joern", "sootup"],
        ],
    )
    def test_ensemble_reachability_java_tp(
        self,
        jenkins_cp: CP,
        jenkins_tp_sink_location: CodeLocation,
        tool_list: list[str],
    ):
        init_context(cp, env_mode="local", debug_mode="debug")
        analyser = EnsembleReachabilityAnalyser(jenkins_cp, tool_list=tool_list)
        res = analyser.reachability_analysis(jenkins_tp_sink_location)
        logger.info(f"Reachability analysis result: {res}")

    @pytest.mark.parametrize(
        "tool_list",
        [
            ["codeql"],
            ["codeql", "sootup"],
            # ["codeql", "joern", "sootup"],
        ],
    )
    def test_ensemble_reachability_java_fp(
        self,
        jenkins_cp: CP,
        jenkins_fp_sink_location: CodeLocation,
        tool_list: list[str],
    ):
        init_context(jenkins_cp, env_mode="local", debug_mode="debug")
        analyser = EnsembleReachabilityAnalyser(jenkins_cp, tool_list=tool_list)
        res = analyser.reachability_analysis(jenkins_fp_sink_location)
        logger.info(f"Reachability analysis result: {res}")
