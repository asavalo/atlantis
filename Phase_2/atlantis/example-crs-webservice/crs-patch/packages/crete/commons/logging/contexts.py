import logging
from typing import TypedDict


class LoggingContext(TypedDict):
    logger: logging.Logger
    logging_prefix: str
