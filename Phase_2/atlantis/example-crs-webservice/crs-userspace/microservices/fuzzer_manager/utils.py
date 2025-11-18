"""Utility functions for fuzzer manager."""
import logging
import os
import subprocess
import psutil
from pathlib import Path
import tarfile
import zstandard as zstd
import shutil

logger = logging.getLogger(__name__)

def run_and_log(cmd, cwd=None):
    """Run a command and return its output."""
    cmd = list(map(str, cmd))
    cwd = os.getcwd() if cwd is None else cwd
    logger.info(f'{" ".join(cmd)}')
    return subprocess.run(cmd, check=False, capture_output=True, cwd=str(cwd))

def rsync(src: Path, dst: Path, delete: bool=False):
    """Synchronize files between source and destination paths."""
    if src.is_dir():
        src = f"{src}/."
    if delete:
        run_and_log(["rsync", "-a", "--delete", src, dst])
    else:
        run_and_log(["rsync", "-a", src, dst])

def unzip(zip_file: Path, dst: Path):
    """Extract a zip file to the destination directory."""
    if not dst.exists():
        dst.mkdir(parents=True, exist_ok=True)
    run_and_log(["unzip", zip_file, "-d", dst])

def extract_tar_zst(src_path, dst_dir):
    """Extract a tar.zst file to the destination directory."""
    with open(src_path, 'rb') as compressed:
        dctx = zstd.ZstdDecompressor()
        with dctx.stream_reader(compressed) as reader:
            with tarfile.open(fileobj=reader, mode='r|') as tar:
                tar.extractall(path=dst_dir)

def flatten_directory(dir: Path):
    """
    Flatten all subfolders of dir, moving files like <dir>/a/b/c.txt to
    <dir>/a_b_c.txt.
    """
    def visit_dir(child_dir: Path):
        for item in child_dir.iterdir():
            if item.is_file():
                item.replace(dir / str(item.relative_to(dir)).replace('/', '_'))
            else:
                visit_dir(item)
                item.rmdir()
    visit_dir(dir)

def filter_to_files(dir: Path):
    for item in dir.iterdir():
        # only allow regular files!
        if not item.is_file():
            # remove this item, whether it's symlink, directory, etc.
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            else:
                try:
                    os.unlink(item)
                except OSError:
                    pass

def reap_children(pid):
    """Clean up child processes of the given process ID."""
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.wait(timeout=1)
            except psutil.NoSuchProcess:
                pass
    except psutil.NoSuchProcess:
        pass 
