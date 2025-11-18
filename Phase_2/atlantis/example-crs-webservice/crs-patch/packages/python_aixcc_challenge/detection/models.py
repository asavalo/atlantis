from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal, Optional

import toml
from pydantic import BaseModel
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as SarifReport,
)

from python_aixcc_challenge.schema.fields import CommitHexString


class AIxCCChallengeFullMode(BaseModel):
    type: Literal["delta", "full", "sarif"] = "full"
    base_ref: CommitHexString

    def checkout_ref(self):
        return self.base_ref


class AIxCCChallengeDeltaMode(BaseModel):
    type: Literal["delta", "full", "sarif"] = "delta"
    base_ref: CommitHexString
    delta_ref: CommitHexString

    def checkout_ref(self):
        return self.delta_ref


class AIxCCChallengeSarifMode(BaseModel):
    type: Literal["delta", "full", "sarif"] = "sarif"
    base_ref: CommitHexString

    def checkout_ref(self):
        return self.base_ref


AIxCCChallengeMode = (
    AIxCCChallengeFullMode | AIxCCChallengeDeltaMode | AIxCCChallengeSarifMode
)


class AIxCCChallengeBlobInfo(BaseModel):
    harness_name: str
    sanitizer_name: str
    blob: str


class AIxCCChallengeProjectDetection(BaseModel):
    vulnerability_identifier: str
    project_name: str
    blobs: list[AIxCCChallengeBlobInfo] = []
    mode: AIxCCChallengeMode
    sarif_report: Optional[str] = None

    @property
    def sarif_report_data(self) -> SarifReport | None:
        if self.sarif_report is None:
            return None
        return SarifReport.model_validate_json(self.sarif_report)

    @staticmethod
    def from_toml(toml_path: Path):
        toml_dict = tomllib.loads(toml_path.read_text())
        return AIxCCChallengeProjectDetection.model_validate(toml_dict)

    def to_toml(self) -> str:
        return toml.dumps(self.model_dump())
