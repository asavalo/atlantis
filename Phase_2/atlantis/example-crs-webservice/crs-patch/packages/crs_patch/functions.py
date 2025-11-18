import logging
from pathlib import Path
from typing import Optional

from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment_pool.services.oss_fuzz import OssFuzzEnvironmentPool
from joblib import Memory
from python_aixcc_challenge.detection.models import (
    AIxCCChallengeMode,
    AIxCCChallengeProjectDetection,
)
from python_aixcc_challenge.project.models import AIxCCChallengeProjectYaml


def get_environment_context(
    logger: logging.Logger, sanitizer_name: str, cache_directory: Path
) -> EnvironmentContext:
    return {
        "logger": logger,
        "logging_prefix": "patch-manager",
        "memory": Memory(cache_directory, verbose=0),
        "sanitizer_name": sanitizer_name,
    }


def init_environment_pool(
    environment_context: EnvironmentContext,
    project_name: str,
    challenge_mode: AIxCCChallengeMode,
    challenge_project_directory: Path,
    crete_cache_directory: Optional[Path] = None,
) -> OssFuzzEnvironmentPool:
    challenge_project_detection = AIxCCChallengeProjectDetection(
        vulnerability_identifier="",
        project_name=project_name,
        mode=challenge_mode,
    )
    challenge_project_yaml = AIxCCChallengeProjectYaml.from_project_name(project_name)
    environment_pool = OssFuzzEnvironmentPool(
        challenge_project_directory=challenge_project_directory,
        challenge_project_detection=challenge_project_detection,
        challenge_project_yaml=challenge_project_yaml,
        cache_directory=crete_cache_directory,
        max_timeout=30 * 60,
    )
    environment_pool.initialize(environment_context)
    return environment_pool
