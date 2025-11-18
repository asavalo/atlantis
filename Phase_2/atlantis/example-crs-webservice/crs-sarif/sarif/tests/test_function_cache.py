import json
import os
import time
from pathlib import Path

import pytest
from loguru import logger

from sarif.context import SarifCacheManager, init_context
from sarif.models import CP, Function
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as AIxCCSarif,
)
from sarif.utils.cache import clear_method_cache
from sarif.validator.preprocess.info_extraction import (
    __get_func_by_line_codeql,
    extract_essential_info,
)
from sarif.validator.reachability.codeql import CodeQLReachabilityAnalyser
from sarif.validator.reachability.introspector import IntrospectorReachabilityAnalyser


def _codeql_db_path(cp: CP) -> Path:
    return Path(f"{os.getenv('BUILD_DIR')}/codeql-db/{cp.name}")


def _function_to_tuple(func: Function):
    return (func.file_name, func.func_name)


class TestFunctionCache:
    def test_introspector_reachability_cache(self, c_cp: CP, jenkins_cp: CP):
        init_context(c_cp, env_mode="local", debug_mode="debug")
        analyser = IntrospectorReachabilityAnalyser(c_cp)

        SarifCacheManager().memory.clear()

        logger.info("First call")
        start_time = time.time()
        first_res = analyser.get_all_reachable_funcs()
        end_time = time.time()
        first_call_time = end_time - start_time
        logger.info(f"First call time: {first_call_time} seconds")

        clear_method_cache(analyser, analyser.get_all_reachable_funcs)

        logger.info("Second call")
        start_time = time.time()
        second_res = analyser.get_all_reachable_funcs()
        end_time = time.time()
        second_call_time = end_time - start_time
        logger.info(f"Second call time: {second_call_time} seconds")

        logger.info("Third call")
        start_time = time.time()
        third_res = analyser.get_all_reachable_funcs()
        end_time = time.time()
        third_call_time = end_time - start_time
        logger.info(f"Third call time: {third_call_time} seconds")

        init_context(cp=jenkins_cp, env_mode="local", debug_mode="debug")
        analyser = IntrospectorReachabilityAnalyser(jenkins_cp)

        logger.info("Different call")
        start_time = time.time()
        different_res = analyser.get_all_reachable_funcs()
        end_time = time.time()
        different_call_time = end_time - start_time
        logger.info(f"Different call time: {different_call_time} seconds")

        assert (
            first_res != []
            and second_res != []
            and third_res != []
            and different_res != []
        )
        assert first_call_time > third_call_time
        assert second_call_time > third_call_time
        assert set(map(_function_to_tuple, second_res)) == set(
            map(_function_to_tuple, first_res)
        )
        assert set(map(_function_to_tuple, third_res)) == set(
            map(_function_to_tuple, first_res)
        )
        assert different_call_time > third_call_time
        assert set(map(_function_to_tuple, different_res)) != set(
            map(_function_to_tuple, third_res)
        )

    def test_codeql_reachability_cache(self, c_cp: CP, jenkins_cp: CP):
        init_context(c_cp, env_mode="local", debug_mode="debug")
        analyser = CodeQLReachabilityAnalyser(c_cp, db_path=_codeql_db_path(c_cp))

        SarifCacheManager().memory.clear()

        logger.info("First call")
        start_time = time.time()
        first_res = analyser.get_all_reachable_funcs()
        end_time = time.time()
        first_call_time = end_time - start_time
        logger.info(f"First call time: {first_call_time} seconds")

        clear_method_cache(analyser, analyser.get_all_reachable_funcs)

        logger.info("Second call")
        start_time = time.time()
        second_res = analyser.get_all_reachable_funcs()
        end_time = time.time()
        second_call_time = end_time - start_time
        logger.info(f"Second call time: {second_call_time} seconds")

        logger.info("Third call")
        start_time = time.time()
        third_res = analyser.get_all_reachable_funcs()
        end_time = time.time()
        third_call_time = end_time - start_time
        logger.info(f"Third call time: {third_call_time} seconds")

        init_context(cp=jenkins_cp, env_mode="local", debug_mode="debug")
        analyser = CodeQLReachabilityAnalyser(
            jenkins_cp, db_path=_codeql_db_path(jenkins_cp)
        )

        logger.info("Different call")
        start_time = time.time()
        different_res = analyser.get_all_reachable_funcs()
        end_time = time.time()
        different_call_time = end_time - start_time
        logger.info(f"Different call time: {different_call_time} seconds")

        assert (
            first_res != []
            and second_res != []
            and third_res != []
            and different_res != []
        )
        assert first_call_time > third_call_time
        assert second_call_time > third_call_time
        assert set(map(_function_to_tuple, second_res)) == set(
            map(_function_to_tuple, first_res)
        )
        assert set(map(_function_to_tuple, third_res)) == set(
            map(_function_to_tuple, first_res)
        )
        assert different_call_time > third_call_time
        assert set(map(_function_to_tuple, third_res)) == set(
            map(_function_to_tuple, first_res)
        )
        assert different_call_time > third_call_time
        assert set(map(_function_to_tuple, different_res)) != set(
            map(_function_to_tuple, third_res)
        )

    def test_info_extraction_cache(self, fp_sarif_path: Path):
        with open(fp_sarif_path) as f:
            sarif_json = json.load(f)

        sarif_model = AIxCCSarif.model_validate(sarif_json)
        sarif_res = sarif_model.runs[0].results[0]

        try:
            loc_function_full_name = sarif_res.locations[0].logicalLocations[0].name
        except IndexError:
            __get_func_by_line_codeql.clear()

            logger.info("First call")
            start_time = time.time()
            first_res = extract_essential_info(fp_sarif_path)
            end_time = time.time()
            first_call_time = end_time - start_time
            logger.info(f"First call time: {first_call_time} seconds")

            logger.info("Second call")
            start_time = time.time()
            second_res = extract_essential_info(fp_sarif_path)
            end_time = time.time()
            second_call_time = end_time - start_time
            logger.info(f"Second call time: {second_call_time} seconds")

            assert first_call_time > second_call_time
            assert first_res == second_res
        else:
            pytest.skip("Already has logical location")
