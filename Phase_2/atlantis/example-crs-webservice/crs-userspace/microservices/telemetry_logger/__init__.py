from base64 import b64encode
import logging
from textwrap import indent
import traceback
import zlib

from kafka import KafkaConsumer
from libatlantis.constants import (
    ALL_TOPICS,
    FUZZER_SEED_SUGGESTIONS_TOPIC,
    FUZZER_SEED_UPDATES_TOPIC,
    FUZZER_SEED_REQUESTS_TOPIC,
)
from libatlantis.service_utils import configure_logger
from libCRS.otel import install_otel_logger

from .config import CONSUMER_ARGS


logger = logging.getLogger(__name__)

TOPIC_DENYLIST = [
    FUZZER_SEED_SUGGESTIONS_TOPIC, # already logged via a checksum in ensembler
    FUZZER_SEED_UPDATES_TOPIC, # too frequent and can contain large data
    FUZZER_SEED_REQUESTS_TOPIC, # also spams logs
]

def run():
    configure_logger("telemetry_service")
    install_otel_logger(action_name="telemetry_service", action_category="building")  # I guess?
    logger.info("Start!")

    topics = list(set(ALL_TOPICS) - set(TOPIC_DENYLIST))
    consumer = KafkaConsumer(*topics, **CONSUMER_ARGS)

    try:
        for msg in consumer:
            try:
                v = msg.value
                v = zlib.compress(v, wbits=-15)
                v = b64encode(v).decode("ascii")
                logger.info(f"{msg.topic} {v}", extra={"topic": msg.topic})

            except KeyboardInterrupt:
                break

            except:
                logger.error(traceback.format_exc())

    finally:
        # Close the consumer to commit our current offset
        consumer.close()
