import os
from pathlib import Path

OSS_FUZZ_DIRECTORY = Path(__file__).parent.parent / ".oss_fuzz"
OSS_FUZZ_PROJECTS_DIRECTORY = OSS_FUZZ_DIRECTORY / "projects"
LANGUAGE_SERVER_PROTOCOL_DIRECTORY = (
    Path(__file__).parent.parent / "language_server_protocol" / "scripts"
)
RR_BACKTRACER_DIRECTORY = Path(__file__).parent.parent / "rr" / "scripts"

OSS_FUZZ_HELPER_FILE = OSS_FUZZ_DIRECTORY / "infra" / "helper.py"
OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY = (
    OSS_FUZZ_DIRECTORY / "build" / "work" / "base-runner-debug"
)
OSS_FUZZ_DEBUGGER_OUT_DIRECTORY = OSS_FUZZ_DIRECTORY / "build" / "out"
OSS_FUZZ_RR_BACKTRACER_WORKING_DIRECTORY = (
    OSS_FUZZ_DIRECTORY / "build" / "work" / "rr-backtracer"
)
OSS_FUZZ_RR_BACKTRACER_OUT_DIRECTORY = (
    OSS_FUZZ_DIRECTORY / "build" / "out" / "rr-backtracer"
)


OSS_FUZZ_BASE_IMAGE_TAG = os.getenv("OSS_FUZZ_BASE_IMAGE_TAG", default="v1.3.0")

TEAM_ATLANTA_DOCKER_REGISTRY = os.getenv("REGISTRY", default="ghcr.io/team-atlanta")
TEAM_ATLANTA_IMAGE_VERSION = os.getenv("IMAGE_VERSION", default="v1.0.0")
