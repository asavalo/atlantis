import sys
import time
from uuid import UUID, uuid4
from vapi_server.models.types import PatchSubmissionResponse, SubmissionStatus
from .redis_util import RedisUtil
from .api_util import (
    capi_submit_patch,
    capi_check_patch_result,
    send_patch_match_request,
)
from .bundle_algo import BundleAlgo
from libCRS import install_otel_logger

install_otel_logger()

from loguru import logger
from crs_webserver.my_crs.crs_manager.log_config import setup_logger

setup_logger()
SLEEP = 10

PATCH_SUBMISSION_ERROR = PatchSubmissionResponse(
    patch_id=UUID("00000000-0000-0000-0000-000000000000"),
    status=SubmissionStatus.SubmissionStatusErrored,
)


class PatchSubmit:
    def __init__(self, patch_id: str):
        self.patch_id = UUID(patch_id)
        self.redis = RedisUtil()
        self.patch_submission = self.redis.get_patch_submission(self.patch_id)
        pov_id = self.redis.get_pov_id_of_patch(self.patch_id)
        self.pov_id = pov_id
        self.info(
            f"Remediated POV {pov_id}, patched_again_pov_ids: {self.patch_submission.patched_again_pov_ids}"
        )

    def __should_be_skipped(self) -> bool:
        return len(self.patch_submission.patched_again_pov_ids) >= 3

    def info(self, msg):
        logger.info(f"[PatchSubmit][{self.patch_id}] {msg}")

    def main(self):
        self.info("Main")
        if self.__should_be_skipped():
            self.info("Skip patch submission because len(patched_again_pov_ids) >= 3")
            return
        if not self.wait_capi_pov_result():
            self.info("Do not submit patch because POV is failed")
            self.__update_capi_result(PATCH_SUBMISSION_ERROR)
            return
        capi_patch_id = self.submit_capi()
        self.redis.incr_state("waiting")
        ret = self.check_capi_result(capi_patch_id)
        if ret.value == SubmissionStatus.SubmissionStatusPassed.value:
            self.redis.decr_state("waiting")
            self.redis.incr_state("succeeded")
            self.submit_capi_bundle()
            self.invoke_sarif_patch_match()
        else:
            self.redis.decr_state("waiting")
            self.redis.incr_state("failed")

    def wait_capi_pov_result(self) -> bool:
        pov_id = self.redis.get_pov_id_of_patch(self.patch_id)
        self.info(f"Wait CAPI POV result of {pov_id}")
        while True:
            res = self.redis.get_pov_submission_response(pov_id)
            if res == None:
                return False
            if res.status.value == SubmissionStatus.SubmissionStatusAccepted.value:
                continue
            return res.status.value == SubmissionStatus.SubmissionStatusPassed.value

    def submit_capi(self):
        self.info("Submit CAPI")
        ret = self.__do_submit_capi()
        self.__update_capi_result(ret)
        return ret.patch_id

    def __do_submit_capi(self):
        self.info(f"Submit Patch to CAPI")
        res = capi_submit_patch(self.patch_submission.patch)
        if res == None:
            self.info("Error in submitting Patch to CAPI")
            return
        self.info(f"[CAPI] Submit patch_id: {res.patch_id}, status: {res.status.value}")
        return PatchSubmissionResponse.model_validate(res.to_dict())

    def __update_capi_result(self, ret: PatchSubmissionResponse):
        key = self.redis.to_patch_capi_key(str(self.patch_id))
        self.redis.write(key, ret.model_dump_json())

    def check_capi_result(self, capi_patch_id):
        self.info("Check CAPI Result")
        while True:
            ret = self.__do_check_capi_result(capi_patch_id)
            if (
                ret != None
                and ret.status.value != SubmissionStatus.SubmissionStatusAccepted.value
            ):
                self.__update_capi_result(ret)
                self.info(f"[CAPI] {ret}")
                return ret.status
            time.sleep(SLEEP)

    def __do_check_capi_result(self, capi_patch_id: UUID):
        res = capi_check_patch_result(capi_patch_id)
        if res == None:
            return None
        self.info(
            f"[CAPI] Check Result patch_id: {res.patch_id}, status: {res.status.value}"
        )
        return PatchSubmissionResponse.model_validate(res.to_dict())

    def submit_capi_bundle(self):
        BundleAlgo(self.info, self.redis).bundle_pov_patch(self.pov_id, self.patch_id)

    def invoke_sarif_patch_match(self):
        self.info("Request sarif patch matching")
        pov_id = self.redis.get_pov_id_of_patch(self.patch_id)
        diff = self.patch_submission.patch
        return send_patch_match_request(pov_id, self.patch_id, diff)


if __name__ == "__main__":
    PatchSubmit(sys.argv[1]).main()
