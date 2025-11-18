#!/usr/bin/env python3

import yaml
import subprocess
from pathlib import Path
import sys
from loguru import logger
import os


root_dir = Path(__file__).parent.parent
fuzzers_yaml = root_dir / "fuzzers.yaml"

with open(fuzzers_yaml, "r") as f:
    fuzzers = yaml.safe_load(f)

for target in fuzzers:
    for fuzzer in fuzzers[target]["fuzzers"]:
        logger.info(f"Building fuzzer: {fuzzer}")
        fuzzer_dir = root_dir / target / fuzzer
        env = os.environ.copy()
        env["DOCKER_BUILDKIT"] = "1"
        subprocess.run(
            [
                "docker",
                "build",
                "-t",
                fuzzer,
                "-f",
                f"{fuzzer_dir}/Dockerfile",
                f"{fuzzer_dir}",
            ],
            env=env,
        )

subprocess.run(["rm", "-rf", "tarballs"], cwd=root_dir)
subprocess.run(["mkdir", "-p", "tarballs"], cwd=root_dir)
for target in fuzzers:
    subprocess.run(
        ["cp", f"{target}/config.yaml", f"tarballs/{target}_config.yaml"], cwd=root_dir
    )
    for fuzzer in fuzzers[target]["fuzzers"]:
        logger.info(f"Saving fuzzer: {fuzzer}")
        subprocess.run(
            ["docker", "save", "-o", f"tarballs/{fuzzer}.tar", fuzzer], cwd=root_dir
        )

logger.info("Compressing tarballs")
subprocess.run(["rm", "-rf", "custom_fuzzers.tar.zst"], check=True, cwd=root_dir)
subprocess.run(
    [
        "tar --sort=name --mtime='UTC 2025-01-01' --owner=0 --group=0 --numeric-owner -cf - -C ./tarballs . | zstd -19 -T0 -o custom_fuzzers.tar.zst"
    ],
    shell=True,
    cwd=root_dir,
)
