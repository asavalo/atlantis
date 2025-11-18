import os
from pathlib import Path
from typing import Literal

import pytest
from loguru import logger

from sarif.context import init_context
from sarif.models import CP, CodeLocation
from sarif.validator.reachability.sootup import SootupReachabilityAnalyser


class TestSootupReachability:
    @pytest.mark.parametrize(
        "mode",
        ["cha", "rta", "pta"],
    )
    def test_sootup_reachability_tp(
        self,
        jenkins_cp: CP,
        jenkins_tp_sink_location: CodeLocation,
        mode: Literal["cha", "rta", "pta"],
    ):
        init_context(jenkins_cp, env_mode="local", debug_mode="debug")
        analyser = SootupReachabilityAnalyser(jenkins_cp, mode=mode)
        res = analyser.reachability_analysis(jenkins_tp_sink_location)
        logger.info(f"Reachability analysis result: {res}")

    @pytest.mark.parametrize(
        "mode",
        ["cha", "rta", "pta"],
    )
    def test_sootup_reachability_fp(
        self,
        jenkins_cp: CP,
        jenkins_fp_sink_location: CodeLocation,
        mode: Literal["cha", "rta", "pta"],
    ):
        init_context(jenkins_cp, env_mode="local", debug_mode="debug")
        analyser = SootupReachabilityAnalyser(jenkins_cp, mode=mode)
        res = analyser.reachability_analysis(jenkins_fp_sink_location)
        logger.info(f"Reachability analysis result: {res}")
