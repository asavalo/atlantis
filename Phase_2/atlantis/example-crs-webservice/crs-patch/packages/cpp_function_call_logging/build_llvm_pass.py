import os
import subprocess
from pathlib import Path

from python_oss_fuzz.path.globals import OSS_FUZZ_BASE_IMAGE_TAG

SCRIPT_DIRECTORY = Path(__file__).parent
DOCKER_IMAGE = f"ghcr.io/aixcc-finals/base-builder:{OSS_FUZZ_BASE_IMAGE_TAG}"
# TODO: make it configurable
CALL_TRACE_LOG_RELATIVE_PATH = Path("out/call_trace.log")

if (SCRIPT_DIRECTORY / "build").exists():
    print("Build directory already exists")
    exit(0)

subprocess.check_call(
    f"docker run --rm -u {os.getuid()}:{os.getgid()} -v {SCRIPT_DIRECTORY}:/app -w /app -e LOG_FILE_PATH=/{CALL_TRACE_LOG_RELATIVE_PATH} {DOCKER_IMAGE} /app/build.sh",
    shell=True,
)
