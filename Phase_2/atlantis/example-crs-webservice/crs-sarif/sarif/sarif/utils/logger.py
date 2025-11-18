import logging
import os
from typing import Any, List, cast

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

SUCCESS = 25  # DEBUG=10, INFO=20, WARNING=30, ERROR=40, CRITICAL=50

custom_theme = Theme(
    {
        "logging.level.success": "bold green",
        "logging.level.debug": "dim white",
        "logging.level.info": "cyan",
        "logging.level.warning": "yellow",
        "logging.level.error": "bold red",
        "logging.level.critical": "bold white on red",
    }
)

console = Console(theme=custom_theme)


class ExtendedLogger(logging.Logger):
    def success(self, msg: object, *args: Any, **kwargs: Any) -> None:
        if self.isEnabledFor(SUCCESS):
            self._log(SUCCESS, msg, args, **kwargs)


class RichLogger(ExtendedLogger):
    def __init__(self, name: str, level: int = logging.NOTSET):
        super().__init__(name, level)

    def setup_rich_handler(self, level: int = logging.INFO) -> None:
        for handler in self.handlers[:]:
            self.removeHandler(handler)

        rich_handler = RichHandler(
            console=console,
            rich_tracebacks=True,
            level=level,
            show_time=True,
            show_path=False,
        )

        formatter = logging.Formatter("%(message)s")
        rich_handler.setFormatter(formatter)

        self.addHandler(rich_handler)


def init_logger(
    level: int = logging.DEBUG,
    logger_names: List[str] = ["SARIF"],
    third_party_level: int = logging.WARNING,
) -> logging.Logger:
    logging.addLevelName(SUCCESS, "SUCCESS")

    logging.setLoggerClass(RichLogger)

    root_logger = logging.getLogger()

    root_logger.setLevel(third_party_level)

    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    rich_handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        level=level,
        show_time=True,
        show_path=False,
    )

    formatter = logging.Formatter("%(message)s")
    rich_handler.setFormatter(formatter)

    root_logger.addHandler(rich_handler)

    for name in logger_names:
        pkg_logger = logging.getLogger(name)
        pkg_logger.setLevel(level)

    # logging.getLogger("requests").propagate = False
    # logging.getLogger("urllib3").propagate = False

    return root_logger


def get_logger(name: str | None = None) -> RichLogger:
    if name is None:
        name = "SARIF"

    return cast(RichLogger, logging.getLogger(name))
