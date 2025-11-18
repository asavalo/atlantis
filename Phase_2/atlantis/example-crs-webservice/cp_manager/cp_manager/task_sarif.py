import sys
from libCRS import install_otel_logger
from .redis_util import RedisUtil
from .api_util import (
    send_sarif_match_request,
)
from loguru import logger
from crs_webserver.my_crs.crs_manager.log_config import setup_logger

setup_logger()
install_otel_logger()


class TaskSarif:
    def __init__(self, key):
        self.redis = RedisUtil()
        self.sarif = self.redis.get_sarif(key)
        self.sarif_id = self.sarif.sarif_id

    def info(self, msg):
        logger.info(f"[TaskSarif][{self.sarif_id}] {msg}")

    def main(self):
        self.info("Send SARIF match request")
        send_sarif_match_request(self.sarif)


if __name__ == "__main__":
    TaskSarif(sys.argv[1]).main()
