#!/usr/bin/env python3

import argparse
import hashlib
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List

# Exclusion patterns\NAMESPACE_MARKER
EXCLUDE_PATTERNS = [
    "ignore-me/",
    "concolic_executor/target/",
    "concolic_executor/libsymcc-rt.so",
    "concolic_executor/symcc-venv/",
    "cpython-3.14/build",
    "LibAFL/target/",
    "LibAFL/libafl_concolic/symcc_runtime/target",
    "LibAFL/libafl_concolic/symcc_runtime_macros/target",
    "z3/build",
    "symcc-pass/build/",
    "atlantis_cc/target/",
    "atlantis_cc/*_wrapper",
    "symqemu-multilang/_build/",
    "symqemu-multilang/python/",
    # This directory contains too much symlinks, so we skip it entirely
    "symqemu-multilang/build/",
    "symqemu-multilang/symqemu-venv/",
    "symqemu-multilang/subprojects/",
    "symqemu-multilang/scripts/",
    # Dynamically created file
    "symqemu-multilang/configure_symqemu.sh",
    "glib-2.66/_build/",
    "glib-2.66/meson-venv/",
    "symcc-fuzzing-engine/build/",
    "symcc-fuzzing-engine/libSymCCFuzzingEngine.a",
    "hash_symcc.py",
    # We won't touch python right? So let's just ignore the entirety of it, it has too much stuff...
    "cpython-3.14/",
    "**/.cache/",
    "**/__pycache__",
]


def hash_directory_git_files(root: Path, git_files: List[str]) -> str:
    """
    Compute a deterministic combined hash of all git-tracked files under `root`.
    Uses BLAKE2b (digest_size=32) for speed and security.
    """
    # Master hasher for the directory signature
    master = hashlib.blake2b(digest_size=32)
    root = root.resolve()

    # Convert relative paths to absolute paths and sort for deterministic order
    file_paths = [
        root / rel_path
        for rel_path in git_files
        if rel_path and (root / rel_path).is_file()
    ]
    file_paths.sort(key=lambda p: str(p.relative_to(root)))

    # Hash each file and update the master hasher
    for fpath in file_paths:
        if not fpath.exists():
            continue  # Skip if file doesn't exist (shouldn't happen with git ls-files)

        rel_path = str(fpath.relative_to(root))
        # Compute file hash
        h = hashlib.blake2b(digest_size=32)
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        file_digest = h.digest()

        # Update master: include relative path, separator, then file digest
        master.update(rel_path.encode("utf-8"))
        master.update(b"\0")
        master.update(file_digest)

    # Return hexadecimal signature
    return master.hexdigest()


def process(directory: Path) -> str:
    """
    Copies `directory` to a temporary location, applying exclusions,
    initializes a git repository, then computes and returns its content hash
    using only files that git would track (respecting .gitignore).
    """
    with tempfile.TemporaryDirectory(prefix="hash_symcc", dir="/tmp") as tmpdir:
        copy_dir = Path(tmpdir) / "out"
        # Prepare rsync arguments
        args = ["rsync", "-a", "--info=none", "--safe-links"]
        for exclude in EXCLUDE_PATTERNS:
            args.append(f"--exclude={exclude}")
        args.extend([str(directory) + os.sep, str(copy_dir)])

        # Perform the copy with exclusions
        subprocess.run(args, check=True)

        # Initialize git repository
        subprocess.run(
            ["git", "init"],
            cwd=copy_dir,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Add all files to git (respects .gitignore)
        subprocess.run(["git", "add", "."], cwd=copy_dir, check=True)

        # Get list of files that git would track
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=copy_dir,
            check=True,
            capture_output=True,
            text=True,
        )
        git_files = result.stdout.strip().split("\n") if result.stdout.strip() else []
        # Compute and return the deterministic directory hash using git-tracked files
        return hash_directory_git_files(copy_dir, git_files)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ultra-fast deterministic directory hash with exclusions"
    )
    parser.add_argument("directory", type=Path, help="Directory to hash recursively")
    args = parser.parse_args()

    if not args.directory.exists():
        print(f"Error: Directory {args.directory} does not exist")
        return 1

    if not args.directory.is_dir():
        print(f"Error: {args.directory} is not a directory")
        return 1

    dir_hash = process(args.directory)
    print(dir_hash)
    return 0


if __name__ == "__main__":
    exit(main())
