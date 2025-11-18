import os
import time
import logging
from loguru import logger
import json
from uuid import UUID
from urllib3.exceptions import MaxRetryError, NewConnectionError
from typing import Optional

from crs_webserver.my_crs.openapi_client import (
    ApiClient,
    Configuration,
    PovApi,
    PatchApi,
    BundleApi,
    BroadcastSarifAssessmentApi,
    TypesArchitecture,
    TypesPOVSubmission,
    TypesPOVSubmissionResponse,
    TypesPatchSubmission,
    TypesPatchSubmissionResponse,
    TypesBundleSubmission,
    TypesBundleSubmissionResponse,
    TypesSarifAssessmentSubmission,
    TypesSarifAssessmentResponse,
)
from crs_webserver.my_crs.crs_manager.log_config import setup_logger
import patch_client
import sarif_client
from vapi_server.models.types import Sarif

setup_logger()

logging.getLogger("urllib3").setLevel(logging.CRITICAL)

RETRY_COUNT = 10
RETRY_INTERVAL = 1  # sleep seconds


def init_api_client() -> ApiClient:
    configuration = Configuration(
        host=os.getenv("COMPETITION_URL"),
        username=os.getenv("COMPETITION_API_KEY_ID"),
        password=os.getenv("COMPETITION_API_KEY_TOKEN"),
    )
    return ApiClient(
        configuration=configuration,
        header_name="ContentType",
        header_value="application/json",
    )


def init_patch_client() -> patch_client.ApiClient:
    task_id = get_task_id()
    configuration = patch_client.Configuration(
        host=f"http://crs-patch-{task_id}",
    )
    return patch_client.ApiClient(
        configuration=configuration,
        header_name="ContentType",
        header_value="application/json",
    )


def init_sarif_client() -> sarif_client.ApiClient:
    task_id = get_task_id()
    configuration = sarif_client.Configuration(
        host=f"http://crs-sarif-{task_id}",
    )
    return sarif_client.ApiClient(
        configuration=configuration,
        header_name="ContentType",
        header_value="application/json",
    )


def get_task_id():
    return os.getenv("TASK_ID")


def capi_submit_pov(
    fuzzer_name: str, sanitizer: str, base64_blob: str
) -> TypesPOVSubmissionResponse:
    api = PovApi(init_api_client())
    payload = TypesPOVSubmission(
        architecture=TypesArchitecture.ArchitectureX8664.value,
        engine="libfuzzer",
        fuzzer_name=fuzzer_name,
        sanitizer=sanitizer,
        testcase=base64_blob,
    ).model_dump()
    response = None
    for i in range(RETRY_COUNT):
        try:
            logger.info(f"capi_submit_pov {i}th")
            response: TypesPOVSubmissionResponse = api.v1_task_task_id_pov_post(
                get_task_id(), payload
            )
            return response
        except (MaxRetryError, NewConnectionError) as e:
            time.sleep(RETRY_INTERVAL)
    return response


def capi_check_pov_result(capi_pov_id: UUID) -> TypesPOVSubmissionResponse:
    api = PovApi(init_api_client())

    response = None
    try:
        response: TypesPOVSubmissionResponse = api.v1_task_task_id_pov_pov_id_get(
            get_task_id(), str(capi_pov_id)
        )
    except (MaxRetryError, NewConnectionError) as e:
        pass
    return response


def capi_submit_patch(base64_patch: str) -> TypesPatchSubmissionResponse:
    api = PatchApi(init_api_client())
    payload = TypesPatchSubmission(patch=base64_patch).model_dump()
    response = None
    for i in range(RETRY_COUNT):
        try:
            logger.info(f"capi_submit_patch {i}th")
            response: TypesPatchSubmissionResponse = api.v1_task_task_id_patch_post(
                get_task_id(), payload
            )
            return response
        except (MaxRetryError, NewConnectionError) as e:
            time.sleep(RETRY_INTERVAL)
    return response


def capi_check_patch_result(capi_patch_id: UUID) -> TypesPatchSubmissionResponse:
    api = PatchApi(init_api_client())
    response = None
    try:
        response: TypesPatchSubmissionResponse = api.v1_task_task_id_patch_patch_id_get(
            get_task_id(), str(capi_patch_id)
        )
    except (MaxRetryError, NewConnectionError) as e:
        pass
    return response


def capi_submit_bundle(
    capi_pov_id: UUID, capi_patch_id: Optional[UUID], sarif_id: Optional[UUID]
) -> TypesBundleSubmissionResponse:
    api = BundleApi(init_api_client())
    patch_id = str(capi_patch_id) if capi_patch_id is not None else None
    sarif_id = str(sarif_id) if sarif_id is not None else None
    payload = TypesBundleSubmission(
        pov_id=str(capi_pov_id), patch_id=patch_id, broadcast_sarif_id=sarif_id
    ).model_dump()
    response = None
    for i in range(RETRY_COUNT):
        try:
            logger.info(f"capi_submit_bundle {i}th")
            response: TypesBundleSubmissionResponse = api.v1_task_task_id_bundle_post(
                get_task_id(), payload
            )
            return response
        except (MaxRetryError, NewConnectionError) as e:
            time.sleep(RETRY_INTERVAL)
    return response


def capi_delete_bundle(bundle_id: UUID) -> str:
    api = BundleApi(init_api_client())
    response = None
    for i in range(RETRY_COUNT):
        try:
            logger.info(f"capi_delete_bundle {i}th")
            response: str = api.v1_task_task_id_bundle_bundle_id_delete(
                get_task_id(), str(bundle_id)
            )
            return response
        except (MaxRetryError, NewConnectionError) as e:
            time.sleep(RETRY_INTERVAL)
    return response


def capi_update_bundle(
    bundle_id: UUID,
    capi_pov_id: UUID,
    capi_patch_id: Optional[UUID],
    capi_sarif_id: Optional[UUID],
) -> TypesBundleSubmissionResponse:
    api = BundleApi(init_api_client())
    payload = TypesBundleSubmission(
        pov_id=str(capi_pov_id),
        patch_id=str(capi_patch_id) if capi_patch_id != None else None,
        broadcast_sarif_id=str(capi_sarif_id) if capi_sarif_id != None else None,
    ).model_dump()
    response = None
    for i in range(RETRY_COUNT):
        try:
            logger.info(f"capi_update_bundle {i}th")
            response: TypesBundleSubmissionResponse = (
                api.v1_task_task_id_bundle_bundle_id_patch(
                    get_task_id(), str(bundle_id), payload
                )
            )
            return response
        except (MaxRetryError, NewConnectionError) as e:
            time.sleep(RETRY_INTERVAL)
    return response


def capi_submit_sarif(
    sarif_id: UUID, assessment: str, description: str
) -> TypesSarifAssessmentResponse:
    api = BroadcastSarifAssessmentApi(init_api_client())
    payload = {"assessment": assessment, "description": description}
    payload = TypesSarifAssessmentSubmission.from_json(json.dumps(payload)).model_dump()
    response = None
    for i in range(RETRY_COUNT):
        try:
            logger.info(f"capi_submit_sarif {i}th")
            response = (
                api.v1_task_task_id_broadcast_sarif_assessment_broadcast_sarif_id_post(
                    get_task_id(), str(sarif_id), payload
                )
            )
            return response
        except (MaxRetryError, NewConnectionError) as e:
            time.sleep(RETRY_INTERVAL)
    return response


def send_patch_request(
    project_name: str,
    harness_name: str,
    sanitizer_name: str,
    blob_data: str,
    pov_id: UUID,
    type: str,
):
    api = patch_client.PatchApi(init_patch_client())
    blob_info = patch_client.BlobInfo(
        harness_name=harness_name,
        sanitizer_name=sanitizer_name,
        blob_data=blob_data,
    )
    request = patch_client.PatchRequest(
        project_name=project_name,
        blobs=[blob_info],
        pov_id=str(pov_id),
        sarif_report=None,
        type=patch_client.TaskType(type),
    ).model_dump()
    while True:
        try:
            return api.v1_patch_post(request)
        except (MaxRetryError, NewConnectionError) as e:
            logger.info("Retry patch request")
            time.sleep(60)


def send_sarif_match_request(sarif: Sarif):
    api = sarif_client.DefaultApi(init_sarif_client())
    request = sarif_client.SARIFMatchRequest(
        metadata=sarif.metadata, sarif=sarif.sarif, sarif_id=str(sarif.sarif_id)
    ).model_dump()
    while True:
        try:
            return api.match_sarif_post(request)
        except (MaxRetryError, NewConnectionError) as e:
            logger.info("Retry sarif match request")
            time.sleep(60)


def send_pov_match_request(pov_id, fuzzer_name, sanitizer, testcase, crash_log):
    api = sarif_client.DefaultApi(init_sarif_client())
    request = sarif_client.POVMatchRequest(
        pov_id=str(pov_id),
        fuzzer_name=fuzzer_name,
        sanitizer=sanitizer,
        testcase=testcase,
        crash_log=crash_log,
    ).model_dump()
    while True:
        try:
            return api.match_pov_post(request)
        except (MaxRetryError, NewConnectionError) as e:
            logger.info("Retry sarif-pov match request")
            time.sleep(60)


def send_pov_sarif_match_request(
    pov_req: sarif_client.POVMatchRequest, sarif_req: sarif_client.SARIFMatchRequest
):
    api = sarif_client.DefaultApi(init_sarif_client())
    request = sarif_client.PoVSarifMatchRequest(
        pov_match_request=pov_req, sarif_match_request=sarif_req
    ).model_dump()
    for i in range(RETRY_COUNT):
        try:
            logger.info(f"send_pov_sarif_match_request {i}th")
            return api.match_pov_sarif_post(request)
        except (MaxRetryError, NewConnectionError) as e:
            logger.info("Retry sarif-pov match request")
            time.sleep(RETRY_INTERVAL)
    return None


def send_patch_match_request(pov_id, patch_id, diff):
    api = sarif_client.DefaultApi(init_sarif_client())
    request = sarif_client.PatchMatchRequest(
        pov_id=str(pov_id), patch_id=str(patch_id), diff=diff
    ).model_dump()
    while True:
        try:
            return api.match_patch_post(request)
        except (MaxRetryError, NewConnectionError) as e:
            logger.info("Retry sarif-patch match request")
            time.sleep(60)
