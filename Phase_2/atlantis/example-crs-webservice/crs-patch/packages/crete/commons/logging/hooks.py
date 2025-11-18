import logging
import os
from logging import FileHandler
from pathlib import Path
from typing import Optional

from rich.logging import RichHandler


def use_logger(
    name: str | None = None, level: str | int = "INFO", logfile: Optional[Path] = None
) -> logging.Logger:
    logging.basicConfig(
        level="WARNING",
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True)],
    )

    match name:
        case None:
            logger = logging.getLogger(__name__)
        case _:
            logger = logging.getLogger(name)

    if logfile:
        if not any(isinstance(handler, FileHandler) for handler in logger.handlers):
            logger.addHandler(FileHandler(logfile))

    if "LOG_LEVEL" in os.environ:
        level = os.environ["LOG_LEVEL"]

    logger.setLevel(level)

    return logger
