import os
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def changed_directory(
    directory: Path,
):
    current_directory = Path.cwd()

    try:
        os.chdir(directory)
        yield
    finally:
        os.chdir(current_directory)
