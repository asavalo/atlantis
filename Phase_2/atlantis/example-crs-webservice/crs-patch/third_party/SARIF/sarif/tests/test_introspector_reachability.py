from typing import Literal

import pytest
from loguru import logger

from sarif.context import init_context
from sarif.models import CP, CodeLocation
from sarif.validator.reachability.introspector import IntrospectorReachabilityAnalyser


class TestIntrospectorReachability:
    def test_introspector_get_all_func_from_harnesses(self, cp: CP):
        init_context(cp, env_mode="local", debug_mode="debug")
        analyser = IntrospectorReachabilityAnalyser(cp)
        analyser.get_all_reachable_funcs()

    @pytest.mark.parametrize(
        "mode",
        ["forward"],
    )
    def test_introspector_reachability_tp(
        self,
        cp: CP,
        tp_sink_location: CodeLocation,
        mode: Literal["forward"],
    ):
        # Run reachability analysis for true positive
        init_context(cp, env_mode="local", debug_mode="debug")
        analyser = IntrospectorReachabilityAnalyser(cp)
        res = analyser.reachability_analysis(tp_sink_location, mode=mode)
        logger.info(f"Reachability analysis result: {res}")

    @pytest.mark.parametrize(
        "mode",
        ["forward"],
    )
    def test_introspector_reachability_fp(
        self,
        cp: CP,
        fp_sink_location: CodeLocation,
        mode: Literal["forward"],
    ):
        init_context(cp, env_mode="local", debug_mode="debug")
        analyser = IntrospectorReachabilityAnalyser(cp)
        res = analyser.reachability_analysis(fp_sink_location, mode=mode)
        logger.info(f"Reachability analysis result: {res}")
