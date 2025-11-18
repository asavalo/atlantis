from contextlib import contextmanager
from typing import Protocol


class TrackerProtocol(Protocol):
    def start(self) -> None:
        """Start tracking resources."""
        ...

    def stop(self) -> None:
        """Stop tracking resources."""
        ...

    def is_exhausted(self) -> bool:
        """Check if this tracker has exhausted its resources.

        Returns:
            bool: True if resources are exhausted, False otherwise.
        """
        ...

    @contextmanager
    def tracking(self):
        self.start()
        try:
            yield
        finally:
            self.stop()
