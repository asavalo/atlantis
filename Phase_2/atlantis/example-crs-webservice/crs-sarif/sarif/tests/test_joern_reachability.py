import os
from pathlib import Path
from typing import Literal

import pytest
from loguru import logger

from sarif.context import init_context
from sarif.models import CP, CodeLocation

# from sarif.scripts.validator import sarif_cli
from sarif.validator.reachability.joern import JoernReachabilityAnalyser

# from click.testing import CliRunner


@pytest.fixture(scope="session")
def joern_cpg_path(cp: CP) -> Path:
    return Path(f"{os.getenv('BUILD_DIR')}/joern-cpg/{cp.name}.cpg.bin")


class TestJoernReachability:
    # @pytest.mark.parametrize("mode", ["forward", "backward"])
    # "line-reachableBy", "func-reachableBy", "callgraph", "backward"
    @pytest.mark.parametrize(
        "mode",
        ["callgraph", "backward"],
        # "mode", ["line-reachableBy", "func-reachableBy", "callgraph", "backward"]
    )
    def test_joern_reachability_tp(
        self,
        cp: CP,
        joern_cpg_path: Path,
        tp_sink_location: CodeLocation,
        mode: Literal["line-reachableBy", "func-reachableBy", "callgraph", "backward"],
    ):
        # Run reachability analysis for true positive
        init_context(cp, env_mode="local", debug_mode="debug")
        analyser = JoernReachabilityAnalyser(cp, cpg_path=joern_cpg_path)
        res = analyser.reachability_analysis(tp_sink_location, mode=mode)
        logger.info(f"Reachability analysis result: {res}")

    @pytest.mark.parametrize(
        "mode",
        ["callgraph", "backward"],
        # "mode", ["line-reachableBy", "func-reachableBy", "callgraph", "backward"]
    )
    def test_joern_reachability_fp(
        self,
        cp: CP,
        joern_cpg_path: Path,
        fp_sink_location: CodeLocation,
        mode: Literal["line-reachableBy", "func-reachableBy", "callgraph", "backward"],
    ):
        init_context(cp, env_mode="local", debug_mode="debug")
        analyser = JoernReachabilityAnalyser(cp, cpg_path=joern_cpg_path)
        res = analyser.reachability_analysis(fp_sink_location, mode=mode)
        logger.info(f"Reachability analysis result: {res}")
