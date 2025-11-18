import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)


def run(cmd: list, env: Dict[str, str] | None = None):
    cmd = list(map(str, cmd))

    logger.info(f'[RUN] {" ".join(cmd)}')

    try:
        ret = subprocess.run(
            cmd,
            check=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
    except:
        pass


def copytree(src: Path, dst: Path, clean: bool = False):
    if clean:
        if dst.exists():
            shutil.rmtree(dst)

    rsync(src, dst)


def rsync(src: Path, dst: Path):
    if src.is_dir():
        src = f"{src}/."

    cmd = ["rsync", "-a", src, dst]

    return run(cmd)
