import importlib.resources as resources
import os
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Literal

from loguru import logger

from sarif.utils.cmd import BaseCommander, DockerCommander

# Configuration
codeql_path = "codeql"
library_path = None


def temporary_root(tmp_root: Path | None = None) -> Path:
    if tmp_root is None:
        tmp_root = tempfile.TemporaryDirectory(prefix="codeql_")

    tmp_root = Path(tmp_root.name)

    if not tmp_root.exists():
        tmp_root.mkdir(parents=True, exist_ok=True)

    return tmp_root


def temporary_path(prefix, suffix) -> Path:
    name = ""

    if prefix:
        name += prefix

    name += uuid.uuid4().hex

    if suffix:
        name += suffix

    return temporary_root() / name


def temporary_dir(create=True, prefix=None, suffix=None) -> Path:
    path = temporary_path(prefix, suffix)

    if create:
        path.mkdir(parents=True, exist_ok=True)

    return path


def temporary_file(create=True, prefix=None, suffix=None) -> Path:
    path = temporary_path(prefix, suffix)

    if create:
        # Create the file using touch like command in pathlib
        path.touch()

    return path


def run(args, *, container_id: str | None = None, timeout: int | None = None):
    command = [codeql_path] + list(map(str, args))

    if container_id:
        runner = DockerCommander(container_id=container_id)
        res = runner.run(command, quiet=False, timeout=timeout)
    else:
        runner = BaseCommander()
        res = runner.run(command, timeout=timeout)

    if res.returncode != 0:
        if res.returncode == -1:
            raise subprocess.TimeoutExpired(
                f"Command {' '.join(command)} timed out after {timeout} seconds"
            )
        else:
            raise RuntimeError(
                f"Command {' '.join(command)} failed with return code {res.returncode}"
            )

    return res


def get_query_path(language: Literal["c", "java"], name: str) -> Path:
    with resources.path(f"sarif.tools.codeql.ql.{language}", name) as path:
        return path


def get_query_content(language: Literal["c", "java"], name: str) -> str:
    with resources.open_text(f"sarif.tools.codeql.ql.{language}", name) as f:
        return f.read()
