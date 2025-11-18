#!/usr/bin/env python
import os
import subprocess

MODEL_VERSION = "1735df80721140a11b299915670d4912aa1ebb35"

HF_TOKEN = os.getenv("P3_HF_TOKEN", None)
if HF_TOKEN is None:
    raise ValueError(
        "P3_HF_TOKEN environment variable is not set. Please set it before running the script."
    )


subprocess.check_call(
    [
        "docker",
        "build",
        "--build-arg",
        f"HF_TOKEN={HF_TOKEN}",
        "--build-arg",
        f"MODEL_VERSION={MODEL_VERSION}",
        "-t",
        "crs-p3",
        "-f",
        "containers/crs-p3/Dockerfile",
        ".",
    ],
)
