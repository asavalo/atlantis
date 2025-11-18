from __future__ import annotations

from typing import Optional

import yaml
from pydantic import BaseModel
from python_oss_fuzz.path.functions import get_oss_fuzz_project_path

from ..language.types import Language


class AIxCCChallengeProjectYaml(BaseModel, extra="allow"):
    language: Language
    main_repo: str  # git url that hosts the project (https://google.github.io/oss-fuzz/getting-started/new-project-guide/#main_repo)

    @staticmethod
    def from_project_name(project_name: str) -> AIxCCChallengeProjectYaml:
        yaml_path = get_oss_fuzz_project_path(project_name) / "project.yaml"
        yaml_dict = yaml.safe_load(yaml_path.read_text())

        return AIxCCChallengeProjectYaml.model_validate(yaml_dict)


class DeltaModeConfig(BaseModel):
    base_commit: str
    ref_commit: str


class FullModeConfig(BaseModel):
    base_commit: str


class CPVDetails(BaseModel):
    name: str
    sanitizer: str
    error_token: str


class HarnessDetails(BaseModel):
    name: str
    path: str
    cpvs: Optional[list[CPVDetails]] = None


class AIxCCChallengeProjectConfig(BaseModel):
    delta_mode: Optional[list[DeltaModeConfig]] = None
    full_mode: FullModeConfig
    harness_files: list[HarnessDetails]

    @staticmethod
    def from_project_name(project_name: str) -> AIxCCChallengeProjectConfig:
        yaml_path = get_oss_fuzz_project_path(project_name) / ".aixcc/config.yaml"
        yaml_dict = yaml.safe_load(yaml_path.read_text())

        return AIxCCChallengeProjectConfig.model_validate(yaml_dict)


class AIxCCChallengeProject(BaseModel):
    project_name: str
    project_yaml: AIxCCChallengeProjectYaml
    config: AIxCCChallengeProjectConfig

    @staticmethod
    def from_project_name(project_name: str) -> AIxCCChallengeProject:
        project_yaml = AIxCCChallengeProjectYaml.from_project_name(project_name)
        config = AIxCCChallengeProjectConfig.from_project_name(project_name)

        return AIxCCChallengeProject(
            project_name=project_name, project_yaml=project_yaml, config=config
        )
