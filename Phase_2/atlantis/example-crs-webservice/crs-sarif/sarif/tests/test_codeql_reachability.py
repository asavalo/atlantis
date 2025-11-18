import os
from pathlib import Path
from typing import Literal

import pytest
from loguru import logger

from sarif.context import init_context
from sarif.models import CP, CodeLocation

# from sarif.scripts.validator import sarif_cli
from sarif.validator.reachability.codeql import CodeQLReachabilityAnalyser

# from click.testing import CliRunner


@pytest.fixture(scope="session")
def codeql_db_path(cp: CP) -> Path:
    return Path(f"{os.getenv('BUILD_DIR')}/codeql-db/{cp.name}")


class TestCodeQLReachability:
    def test_codeql_get_all_func_from_harnesses(self, cp: CP, codeql_db_path: Path):
        init_context(cp, env_mode="local", debug_mode="debug")
        analyser = CodeQLReachabilityAnalyser(cp, db_path=codeql_db_path)
        analyser.get_all_reachable_funcs()

    # @pytest.mark.parametrize("mode", ["forward", "backward"])
    @pytest.mark.parametrize("mode", ["forward"])
    def test_codeql_reachability_tp(
        self,
        cp: CP,
        codeql_db_path: Path,
        tp_sink_location: CodeLocation,
        mode: Literal["forward", "backward"],
    ):
        # Run reachability analysis for true positive
        init_context(cp, env_mode="local", debug_mode="debug")
        analyser = CodeQLReachabilityAnalyser(cp, db_path=codeql_db_path)
        res = analyser.reachability_analysis(tp_sink_location, mode=mode)
        logger.info(f"Reachability analysis result: {res}")

    @pytest.mark.parametrize("mode", ["forward"])
    def test_codeql_reachability_fp(
        self,
        cp: CP,
        codeql_db_path: Path,
        fp_sink_location: CodeLocation,
        mode: Literal["forward", "backward"],
    ):
        init_context(cp, env_mode="local", debug_mode="debug")
        analyser = CodeQLReachabilityAnalyser(cp, db_path=codeql_db_path)
        res = analyser.reachability_analysis(fp_sink_location, mode=mode)
        logger.info(f"Reachability analysis result: {res}")
