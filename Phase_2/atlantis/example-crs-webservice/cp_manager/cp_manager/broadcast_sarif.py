import os
import sys
from uuid import UUID, uuid4
from pathlib import Path
from vapi_server.models.types import SarifAssessmentBroadcast
from libCRS import install_otel_logger
from .redis_util import RedisUtil
from loguru import logger
from crs_webserver.my_crs.crs_manager.log_config import setup_logger

setup_logger()

install_otel_logger()

SHARED = Path("/shared-crs-fs")
DUMMY_UUID = UUID("00000000-0000-0000-0000-000000000000")
TASK_ID = os.getenv("TASK_ID", str(DUMMY_UUID))
SARIF_ANALYSIS_RESULT_PATH = SHARED / TASK_ID / "sarif-analysis-result"


class BroadcastSarif:
    def __init__(self, sarif_id: str):
        self.redis = RedisUtil()
        self.sarif_id = sarif_id

    def info(self, msg):
        logger.info(f"[BroadcastSarif][{self.sarif_id}] {msg}")

    def main(self):
        self.info("Starting broadcast_sarif")
        key = self.redis.to_sarif_broadcast_key(self.sarif_id)
        result = self.redis.read(key)
        sarif_broadcast = SarifAssessmentBroadcast.model_validate_json(result)
        if result == None:
            self.info("No result found")
            return
        dir = SARIF_ANALYSIS_RESULT_PATH / sarif_broadcast.fuzzer_name
        os.makedirs(dir, exist_ok=True)
        result_path = dir / f"{self.sarif_id}.json"
        result_path.write_text(result)
        self.info(f"Result written to {result_path}")


if __name__ == "__main__":
    BroadcastSarif(sys.argv[1]).main()
