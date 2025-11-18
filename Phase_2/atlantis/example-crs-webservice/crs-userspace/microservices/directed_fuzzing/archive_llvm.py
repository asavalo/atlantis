#!/usr/bin/env python3

import subprocess
from pathlib import Path
from argparse import ArgumentParser

def filter_files(output: str) -> list[str]:
    lines = output.splitlines()
    return [
        line
        for line in lines
        if Path(line).is_file()
    ]
        

def main(workdir: Path, packages: list[str]):
    """
    Get dependencies for llvm and clang, and archive.
    """
    assert workdir.is_dir(), f"{workdir} is not directory"

    subprocess.run(["apt-get", "update"], check=True)

    install_cmd = ["apt-get", "install", "-y", *packages]
    subprocess.run(install_cmd, check=True)
    
    results = [
        subprocess.run(["dpkg", "-L", package], capture_output=True, text=True, check=True)
        for package in packages
    ]

    files = []
    for result in results:
        files.extend(filter_files(result.stdout))

    tar_target = workdir / "packages.tar.gz"
    subprocess.run(["tar", "czf", tar_target, *files])

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("workdir", type=Path)
    parser.add_argument("packages", nargs="+")
    args = parser.parse_args()
    main(args.workdir, args.packages)
