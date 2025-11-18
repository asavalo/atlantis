import asyncio
import base64
import glob
import hashlib
import json
import logging
import os
import random
import time
from pathlib import Path
from uuid import UUID

from fastapi import HTTPException, Request
from langchain_openai import ChatOpenAI
from openai import RateLimitError
from openapi_client.models.types_assessment import TypesAssessment
from pydantic import ValidationError

from crs_sarif.models.models import (
    PatchMatchRequest,
    POVMatchRequest,
    SarifAnalysisResult,
    SarifAssessmentResult,
    SARIFMatchRequest,
    SarifReachabilityResult,
    PoVSarifMatchRequest,
    PoVSarifMatchResponse,
    PoVPatchSarifMatchRequest,
    PoVPatchSarifMatchResponse,
)
from crs_sarif.services.analyser import AnalyserService
from crs_sarif.utils.context import CRSEnv
from crs_sarif.utils.corpus_naming_hash import get_corpus_hash
from crs_sarif.utils.dir_setting import CRSDirSetting
from crs_sarif.utils.redis_util import RedisUtil
from crs_sarif.utils.vapi_client import VapiClient
from sarif.context import SarifServerManager
from sarif.matcher import (
    Coverage,
    CrashReport,
    SarifPovMatchingStrategy,
    match_sarif_coverage,
    match_sarif_patch,
    match_sarif_pov,
)
from sarif.matcher.agent.state import SarifMatchingAction
from sarif.matcher.agent.workflow import SarifMatchingAgent
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as AIxCCSarif,
)
from sarif.validator.preprocess.info_extraction import extract_essential_info
from sarif.validator.reachability.base import BaseReachabilityAnalyser
from sarif.validator.reachability.callgraph import CallGraph
from sarif.validator.reachability.codeql import CodeQLReachabilityAnalyser

logger = logging.getLogger(__name__)

NO_POV_SARIF_MATCH_THRESHOLD = 0.18
NO_PATCH_SARIF_MATCH_THRESHOLD = 0.1

MODEL = ChatOpenAI(model="claude-3-7-sonnet-20250219").with_retry(
    stop_after_attempt=20,
    wait_exponential_jitter=True,
    retry_if_exception_type=(Exception,),
)


def _get_matching_agent():
    return SarifMatchingAgent(llm=MODEL, src_dir=str(CRSEnv().cp_src_path))


def _request_generate_coverage(pov_obj: POVMatchRequest) -> None:
    coverage_request_dir = CRSEnv().coverage_request_shared_dir / pov_obj.fuzzer_name
    if not coverage_request_dir.exists():
        coverage_request_dir.mkdir(parents=True, exist_ok=True)

    corpus_data = base64.b64decode(pov_obj.testcase)
    corpus_hash = get_corpus_hash(corpus_data)
    coverage_request_file = coverage_request_dir / corpus_hash

    with open(coverage_request_file, "wb") as f:
        f.write(corpus_data)


async def _get_coverage(pov_obj: POVMatchRequest, sleep_count: int = 90) -> Coverage:
    coverage_dir = CRSEnv().coverage_shared_dir / pov_obj.fuzzer_name

    blob_data = base64.b64decode(pov_obj.testcase)
    corpus_hash = get_corpus_hash(blob_data)
    coverage_file = Path(str(coverage_dir / corpus_hash) + ".cov")

    if coverage_file.exists():
        with open(coverage_file, "r") as f:
            coverage_raw_data = f.read()
    else:
        _request_generate_coverage(pov_obj)
        for _ in range(sleep_count):
            await asyncio.sleep(10)
            if coverage_file.exists():
                with open(coverage_file, "r") as f:
                    coverage_raw_data = f.read()
                break
        else:
            return Coverage.model_validate({})

    coverage_data = Coverage.from_coverage_file(coverage_raw_data)
    return coverage_data


async def match_pov(pov_obj: POVMatchRequest):
    logger.info(f"match_pov_request : {pov_obj.pov_id}")
    if pov_obj is None:
        return

    RedisUtil().set_pov_match_request(pov_obj)

    patch_match_requests = RedisUtil().get_all_patch_match_requests()
    for patch_match_request in patch_match_requests:
        if patch_match_request.pov_id == pov_obj.pov_id:
            patch_obj = patch_match_request
            logger.info(
                f"Invoke crash-patch matching: {pov_obj.pov_id}-{patch_obj.patch_id}"
            )
            break
    else:
        logger.info(
            f"No matching PatchMatchRequest found for POVMatchRequest: {pov_obj.pov_id}"
        )
        logger.info(f"Invoke crash-only matching: {pov_obj.pov_id}")
        patch_obj = None

    crashlog = base64.b64decode(pov_obj.crash_log).decode("utf-8", errors="ignore")
    if patch_obj is not None:
        patch = base64.b64decode(patch_obj.diff).decode("utf-8", errors="ignore")
    else:
        patch = None

    sarif_match_requests = RedisUtil().get_all_sarif_match_requests()
    for sarif_obj in sarif_match_requests:
        sarif = json.dumps(sarif_obj.sarif, indent=4)
        if patch is None:
            logger.info(f"Matching sarif({sarif_obj.sarif_id}) - pov({pov_obj.pov_id})")
        else:
            logger.info(
                f"Matching sarif({sarif_obj.sarif_id}) - pov({pov_obj.pov_id}) - patch({patch_obj.patch_id})"
            )
        try:
            matching_agent = _get_matching_agent()
            result = matching_agent.invoke(
                sarif=sarif,
                testcase=None,
                crash_log=crashlog,
                patch_diff=patch,
            )
        except Exception as e:
            logger.error(
                f"Error matching sarif({sarif_obj.sarif_id}) - pov({pov_obj.pov_id}): {e}"
            )
            continue
        logger.info(f"Matching Result: {result['next_action']}")
        if result["next_action"] == SarifMatchingAction.MATCHED.value:
            VapiClient().submit_sarif(
                assessment=TypesAssessment.CORRECT,
                sarif_id=str(sarif_obj.sarif_id),
                pov_id=str(pov_obj.pov_id),
                description=f"Valid because we found a matching pov({pov_obj.pov_id})",
            )
            RedisUtil().delete_sarif_match_request(sarif_obj.sarif_id)
            return

    # coverage = await _get_coverage(pov_obj)
    # sarif_match_requests = RedisUtil().get_all_sarif_match_requests()

    # matching_results = list()
    # for sarif_match_request in sarif_match_requests:
    #     sarif_report = AIxCCSarif.model_validate(sarif_match_request.sarif)
    #     match_prob = match_sarif_coverage(sarif_report, coverage)
    #     matching_results.append((sarif_match_request.sarif_id, match_prob))

    # matching_results.sort(key=lambda x: x[1], reverse=True)

    # if (
    #     len(matching_results) > 0
    #     and matching_results[0][1] > NO_POV_SARIF_MATCH_THRESHOLD
    # ):
    #     VapiClient().submit_sarif(
    #         assessment=TypesAssessment.CORRECT,
    #         sarif_id=str(matching_results[0][0]),
    #         pov_id=str(pov_obj.pov_id),
    #         description="Valid because we found a matching POV",
    #     )
    #     RedisUtil().delete_sarif_match_request(sarif_obj.sarif_id)
    #     return


async def match_sarif(sarif_obj: SARIFMatchRequest):
    logger.info(f"match_sarif_request : {sarif_obj.sarif_id}")
    if sarif_obj is None:
        return

    RedisUtil().set_sarif_match_request(sarif_obj)

    sarif = json.dumps(sarif_obj.sarif, indent=4)

    with open(
        CRSEnv().original_sarif_shared_dir / f"{sarif_obj.sarif_id}.sarif", "w"
    ) as f:
        f.write(sarif)

    pov_match_requests = RedisUtil().get_all_pov_match_requests()
    patch_match_requests = RedisUtil().get_all_patch_match_requests()

    for pov_obj in pov_match_requests:
        crashlog = base64.b64decode(pov_obj.crash_log).decode("utf-8", errors="ignore")
        for patch_obj in patch_match_requests:
            if pov_obj.pov_id == patch_obj.pov_id:
                logger.info(
                    f"Invoke crash-patch matching: {pov_obj.pov_id}-{patch_obj.patch_id}"
                )
                patch = base64.b64decode(patch_obj.diff).decode(
                    "utf-8", errors="ignore"
                )
                break
        else:
            logger.info(f"Invoke crash-only matching: {pov_obj.pov_id}")
            patch = None

        if patch is None:
            logger.info(f"Matching sarif({sarif_obj.sarif_id}) - pov({pov_obj.pov_id})")
        else:
            logger.info(
                f"Matching sarif({sarif_obj.sarif_id}) - pov({pov_obj.pov_id}) - patch({patch_obj.patch_id})"
            )
        try:
            matching_agent = _get_matching_agent()
            result = matching_agent.invoke(
                sarif=sarif,
                testcase=None,
                crash_log=crashlog,
                patch_diff=patch,
            )
        except Exception as e:
            logger.error(
                f"Error matching sarif({sarif_obj.sarif_id}) - pov({pov_obj.pov_id}): {e}"
            )
            continue
        logger.info(f"Matching Result: {result['next_action']}")
        if result["next_action"] == SarifMatchingAction.MATCHED.value:
            VapiClient().submit_sarif(
                assessment=TypesAssessment.CORRECT,
                sarif_id=str(sarif_obj.sarif_id),
                pov_id=str(pov_obj.pov_id),
                description=f"Valid because we found a matching pov({pov_obj.pov_id})",
            )
            RedisUtil().delete_sarif_match_request(sarif_obj.sarif_id)
            return

    if CRSEnv().analyser_init_done:
        sarif_analysis_results = await AnalyserService().get_analysis_result(sarif_obj)

        for sarif_analysis_result in sarif_analysis_results:
            AnalyserService().broadcast_analysis_result(sarif_analysis_result)
    else:
        logger.warning(
            "Analyser is not initialized, save the request and skip sarif analysis"
        )

    # sarif_report = AIxCCSarif.model_validate(sarif_obj.sarif)

    # pov_match_requests = RedisUtil().get_all_pov_match_requests()
    # matching_results = list()
    # for pov_match_request in pov_match_requests:
    #     coverage = await _get_coverage(pov_match_request)
    #     prob = match_sarif_coverage(sarif_report, coverage)
    #     matching_results.append((pov_match_request.pov_id, prob))

    # if (
    #     len(matching_results) > 0
    #     and matching_results[0][1] > NO_POV_SARIF_MATCH_THRESHOLD
    # ):
    #     VapiClient().submit_sarif(
    #         assessment=TypesAssessment.CORRECT,
    #         sarif_id=str(sarif_obj.sarif_id),
    #         pov_id=str(matching_results[0][0]),
    #         description="Valid because we found a matching POV",
    #     )
    #     RedisUtil().delete_sarif_match_request(sarif_obj.sarif_id)
    #     return

    # patch_match_requests = RedisUtil().get_all_patch_match_requests()
    # matching_results = list()
    # for patch_match_request in patch_match_requests:
    #     patch_diff = patch_match_request.diff
    #     prob = match_sarif_patch(sarif_report, patch_diff)
    #     matching_results.append((patch_match_request.pov_id, prob))

    # if (
    #     len(matching_results) > 0
    #     and matching_results[0][1] > NO_PATCH_SARIF_MATCH_THRESHOLD
    # ):
    #     VapiClient().submit_sarif(
    #         assessment=TypesAssessment.CORRECT,
    #         sarif_id=str(sarif_obj.sarif_id),
    #         pov_id=str(matching_results[0][0]),
    #         description="Valid because we found a matching patch",
    #     )
    #     RedisUtil().delete_sarif_match_request(sarif_obj.sarif_id)
    #     return


async def match_patch(patch_obj: PatchMatchRequest):
    logger.info(f"match_patch_request : {patch_obj.patch_id}")
    if patch_obj is None:
        return

    RedisUtil().set_patch_match_request(patch_obj)

    pov_match_requests = RedisUtil().get_all_pov_match_requests()
    for pov_match_request in pov_match_requests:
        if pov_match_request.pov_id == patch_obj.pov_id:
            pov_obj = pov_match_request
            break
    else:
        logger.info(
            f"No matching POVMatchRequest found for patch_obj: {patch_obj.patch_id}"
        )
        return

    crashlog = base64.b64decode(pov_obj.crash_log).decode("utf-8", errors="ignore")
    patch = base64.b64decode(patch_obj.diff).decode("utf-8", errors="ignore")

    sarif_match_requests = RedisUtil().get_all_sarif_match_requests()
    for sarif_obj in sarif_match_requests:
        sarif = json.dumps(sarif_obj.sarif, indent=4)
        logger.info(
            f"Matching sarif({sarif_obj.sarif_id}) - pov({pov_obj.pov_id}) - patch({patch_obj.patch_id})"
        )
        try:
            matching_agent = _get_matching_agent()
            result = matching_agent.invoke(
                sarif=sarif,
                testcase=None,
                crash_log=crashlog,
                patch_diff=patch,
            )
        except Exception as e:
            logger.error(
                f"Error matching sarif({sarif_obj.sarif_id}) - pov({pov_obj.pov_id}): {e}"
            )
            continue
        logger.info(f"Matching Result: {result['next_action']}")
        if result["next_action"] == SarifMatchingAction.MATCHED.value:
            VapiClient().submit_sarif(
                assessment=TypesAssessment.CORRECT,
                sarif_id=str(sarif_obj.sarif_id),
                pov_id=str(pov_obj.pov_id),
                description=f"Valid because we found a matching pov-patch({pov_obj.pov_id}-{patch_obj.patch_id})",
            )
            RedisUtil().delete_sarif_match_request(sarif_obj.sarif_id)
            return

    # patch_diff = patch_obj.diff
    # sarif_match_requests = RedisUtil().get_all_sarif_match_requests()

    # matching_results = list()
    # for sarif_match_request in sarif_match_requests:
    #     sarif_report = AIxCCSarif.model_validate(sarif_match_request.sarif)
    #     prob = match_sarif_patch(sarif_report, patch_diff)
    #     matching_results.append((sarif_match_request.sarif_id, prob))

    # matching_results.sort(key=lambda x: x[1], reverse=True)

    # if len(matching_results) > 0 and matching_results[0][1] > 0.1:
    #     VapiClient().submit_sarif(
    #         assessment=TypesAssessment.CORRECT,
    #         sarif_id=str(matching_results[0][0]),
    #         pov_id=str(patch_obj.pov_id),
    #         description="Valid because we found a matching patch",
    #     )
    #     RedisUtil().delete_sarif_match_request(sarif_obj.sarif_id)


async def match_pov_sarif(body: PoVSarifMatchRequest):
    pov_match_request = body.pov_match_request
    sarif_match_request = body.sarif_match_request

    crashlog = base64.b64decode(pov_match_request.crash_log).decode(
        "utf-8", errors="ignore"
    )
    sarif = json.dumps(sarif_match_request.sarif, indent=4)

    matching_agent = _get_matching_agent()

    try:
        result = matching_agent.invoke(
            sarif=sarif,
            testcase=None,
            crash_log=crashlog,
            patch_diff=None,
        )
    except Exception as e:
        logger.error(
            f"Error matching sarif({sarif_match_request.sarif_id}) - pov({pov_match_request.pov_id}): {e}"
        )
        RedisUtil().set_pov_sarif_match_request(
            pov_match_request.pov_id,
            sarif_match_request.sarif_id,
            PoVSarifMatchResponse.failed,
        )
        return

    if result["next_action"] == SarifMatchingAction.MATCHED.value:
        RedisUtil().set_pov_sarif_match_request(
            pov_match_request.pov_id,
            sarif_match_request.sarif_id,
            PoVSarifMatchResponse.matched,
        )
    else:
        RedisUtil().set_pov_sarif_match_request(
            pov_match_request.pov_id,
            sarif_match_request.sarif_id,
            PoVSarifMatchResponse.unmatched,
        )


async def match_pov_patch_sarif(body: PoVPatchSarifMatchRequest):
    pov_match_request = body.pov_match_request
    patch_match_request = body.patch_match_request
    sarif_match_request = body.sarif_match_request

    crashlog = base64.b64decode(pov_match_request.crash_log).decode(
        "utf-8", errors="ignore"
    )
    patch = base64.b64decode(patch_match_request.diff).decode("utf-8", errors="ignore")
    sarif = json.dumps(sarif_match_request.sarif, indent=4)

    matching_agent = _get_matching_agent()

    try:
        result = matching_agent.invoke(
            sarif=sarif,
            testcase=None,
            crash_log=crashlog,
            patch_diff=patch,
        )
    except Exception as e:
        logger.error(
            f"Error matching sarif({sarif_match_request.sarif_id}) - pov({pov_match_request.pov_id}) - patch({patch_match_request.patch_id}): {e}"
        )
        RedisUtil().set_pov_patch_sarif_match_request(
            pov_match_request.pov_id,
            patch_match_request.patch_id,
            sarif_match_request.sarif_id,
            PoVPatchSarifMatchResponse.failed,
        )
        return

    if result["next_action"] == SarifMatchingAction.MATCHED.value:
        RedisUtil().set_pov_patch_sarif_match_request(
            pov_match_request.pov_id,
            patch_match_request.patch_id,
            sarif_match_request.sarif_id,
            PoVPatchSarifMatchResponse.matched,
        )
    else:
        RedisUtil().set_pov_patch_sarif_match_request(
            pov_match_request.pov_id,
            patch_match_request.patch_id,
            sarif_match_request.sarif_id,
            PoVPatchSarifMatchResponse.unmatched,
        )
