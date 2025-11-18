from pathlib import Path

from .globals import OSS_FUZZ_PROJECTS_DIRECTORY


def get_oss_fuzz_project_path(project_name: str) -> Path:
    return OSS_FUZZ_PROJECTS_DIRECTORY / project_name
