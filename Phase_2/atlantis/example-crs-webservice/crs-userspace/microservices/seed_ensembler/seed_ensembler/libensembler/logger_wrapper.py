from collections.abc import Mapping
from contextlib import contextmanager
import json
from logging import Filter, Handler, Logger, LogRecord, getLogger as loggingGetLogger
import sys
import threading

if sys.version_info >= (3, 11):
    from typing import TYPE_CHECKING
    if TYPE_CHECKING:
        from typing import Self


class LoggerWrapper:
    """
    Wrapper around a logging.Logger object that adds utilities for
    - automatic flushing of handlers, and
    - conveniently logging structured data
    """
    logger: Logger
    tls: threading.local

    def __init__(self, logger: Logger):
        self.logger = logger
        self.tls = threading.local()

    @property
    def name(self) -> str:
        return self.logger.name

    @property
    def level(self) -> int:
        return self.logger.level

    @property
    def parent(self) -> Logger | None:
        return self.logger.parent

    @property
    def propagate(self) -> bool:
        return self.logger.propagate
    @propagate.setter
    def propagate(self, value: bool) -> None:
        self.logger.propagate = value

    @property
    def handlers(self) -> list[Handler]:
        return self.logger.handlers

    @property
    def disabled(self) -> bool:
        return self.logger.disabled

    def setLevel(self, level: int | str) -> None:
        return self.logger.setLevel(level)

    def isEnabledFor(self, level: int) -> bool:
        return self.logger.isEnabledFor(level)

    def getEffectiveLevel(self) -> int:
        return self.logger.getEffectiveLevel()

    def getChild(self, suffix: str) -> Logger:
        return self.logger.getChild(suffix)

    def getChildren(self) -> set[Logger]:
        return self.logger.getChildren()

    @contextmanager
    def session(self):
        """
        This context manager ensures that all handlers are flushed at
        the end of its code block. Can safely be nested: inner sessions
        won't do anything in particular, and handlers will be flushed
        when the outermost session block ends.
        """
        if hasattr(self.tls, 'is_session_active') and self.tls.is_session_active:
            yield
            return

        self.tls.is_session_active = True

        try:
            yield

        finally:
            self.tls.is_session_active = False

            for handler in self.logger.handlers:
                handler.flush()

    @contextmanager
    def _logging_wrapper(self, msg: object):
        if not isinstance(msg, str):
            msg = json.dumps(msg)

        with self.session():
            yield msg

    def debug(self, msg: object, *args, **kwargs) -> None:
        with self._logging_wrapper(msg) as msg:
            self.logger.debug(msg, *args, **kwargs)

    def info(self, msg: object, *args, **kwargs) -> None:
        with self._logging_wrapper(msg) as msg:
            self.logger.info(msg, *args, **kwargs)

    def warning(self, msg: object, *args, **kwargs) -> None:
        with self._logging_wrapper(msg) as msg:
            self.logger.warning(msg, *args, **kwargs)

    def warn(self, msg: object, *args, **kwargs) -> None:
        self.warning(msg, *args, **kwargs)

    def error(self, msg: object, *args, **kwargs) -> None:
        with self._logging_wrapper(msg) as msg:
            self.logger.error(msg, *args, **kwargs)

    def critical(self, msg: object, *args, **kwargs) -> None:
        with self._logging_wrapper(msg) as msg:
            self.logger.critical(msg, *args, **kwargs)

    def log(self, level: int, msg: object, *args, **kwargs) -> None:
        with self._logging_wrapper(msg) as msg:
            self.logger.log(level, msg, *args, **kwargs)

    def exception(self, msg: object, *args, **kwargs) -> None:
        with self._logging_wrapper(msg) as msg:
            self.logger.exception(msg, *args, **kwargs)

    def addFilter(self, filter: Filter) -> None:
        return self.logger.addFilter(filter)

    def removeFilter(self, filter: Filter) -> None:
        return self.logger.removeFilter(filter)

    def filter(self, record: LogRecord) -> bool | LogRecord:
        return self.logger.filter(record)

    def addHandler(self, hdlr: Handler) -> None:
        return self.logger.addHandler(hdlr)

    def removeHandler(self, hdlr: Handler) -> None:
        return self.logger.removeHandler(hdlr)

    def findCaller(self, stack_info: bool = False, stacklevel: int = 1) -> tuple[str, int, str, str | None]:
        return self.logger.findCaller(stack_info, stacklevel)

    def handle(self, record: LogRecord) -> None:
        return self.logger.handle(record)

    # signature taken from typeshed; complex types just replaced with
    # object because nobody actually cares
    def makeRecord(
        self,
        name: str,
        level: int,
        fn: str,
        lno: int,
        msg: object,
        args: object,
        exc_info: object | None,
        func: str | None = None,
        extra: Mapping[str, object] | None = None,
        sinfo: str | None = None,
    ) -> LogRecord:
        return self.logger.makeRecord(name, level, fn, lno, msg, args, exc_info, func, extra, sinfo)

    def hasHandlers(self) -> bool:
        return self.logger.hasHandlers()

    @classmethod
    def getLogger(cls, name: str | None) -> 'Self':
        """
        Convenience function so you can quickly get a wrapped logger
        without having to `import logging` yourself
        """
        return cls(loggingGetLogger(name))

    def event(self, name: str, msg: object) -> None:
        """
        Custom logging event that prepends a string to a logged object,
        so it's easy to find in otel logs
        """
        with self._logging_wrapper(msg) as msg:
            self.logger.info(f'{name}:{msg}')
