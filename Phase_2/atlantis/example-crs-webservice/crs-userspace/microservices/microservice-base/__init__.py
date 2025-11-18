# external
import logging
from google.protobuf.message import Message
# libs
from libatlantis.service_utils import service_callback, configure_logger
from libCRS.otel import install_otel_logger
# internal
from . import config

logger = logging.getLogger(config.NAME)

def run():
    configure_logger(config.NAME)
    install_otel_logger(action_name=config.NAME, action_category=config.CATEGORY)
    logger.info("Start!")
