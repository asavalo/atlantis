import os
import sys
from uuid import UUID
from pathlib import Path

from .redis_util import RedisUtil
from vapi_server.models.types import Assessment
from .api_util import (
    capi_submit_sarif,
)
from .bundle_algo import BundleAlgo
from libCRS import install_otel_logger


from loguru import logger
from crs_webserver.my_crs.crs_manager.log_config import setup_logger

setup_logger()
install_otel_logger()

SHARED = Path("/shared-crs-fs")
DUMMY_UUID = UUID("00000000-0000-0000-0000-000000000000")
TASK_ID = os.getenv("TASK_ID", str(DUMMY_UUID))
SARIF_ANALYSIS_RESULT_PATH = SHARED / TASK_ID / "sarif-analysis-result"


class SarifSubmit:
    def __init__(self, sarif_id: str):
        self.redis = RedisUtil()
        self.sarif_submission = self.redis.get_sarif_submission(sarif_id)
        self.sarif_id = self.sarif_submission.sarif_id

    def info(self, msg):
        logger.info(f"[SarifSubmit][{self.sarif_id}] {msg}")

    def main(self):
        if self.submit_capi():
            self.broadcast_sarif_done()
            self.submit_capi_bundle()

    def submit_capi(self) -> (UUID, bool):
        self.info("Submit SARIF Assessment to CAPI")
        res = capi_submit_sarif(
            self.sarif_id,
            self.sarif_submission.assessment.value,
            self.sarif_submission.description,
        )
        if res == None:
            self.info("Error in submitting SARIF Assessment to CAPI")
            return False
        self.info(
            f"[CAPI] Submit sarif_id: {self.sarif_id}, status: {res.status.value}"
        )
        return res.status.value == "accepted"

    def submit_capi_bundle(self):
        if self.sarif_submission.pov_id == None:
            return
        if self.sarif_submission.assessment.value != Assessment.AssessmentCorrect.value:
            return
        BundleAlgo(self.info, self.redis).bundle_pov_sarif(
            self.sarif_submission.pov_id, self.sarif_id
        )

    def broadcast_sarif_done(self):
        if self.sarif_submission.pov_id == None:
            return
        if self.sarif_submission.assessment.value != Assessment.AssessmentCorrect.value:
            return
        pov_submission = self.redis.get_pov_submission(self.sarif_submission.pov_id)
        dir = SARIF_ANALYSIS_RESULT_PATH / pov_submission.fuzzer_name
        os.makedirs(dir, exist_ok=True)
        result_path = dir / f"{self.sarif_id}.done"
        result_path.touch()
        self.info(f"Touch {result_path}")


if __name__ == "__main__":
    SarifSubmit(sys.argv[1]).main()
