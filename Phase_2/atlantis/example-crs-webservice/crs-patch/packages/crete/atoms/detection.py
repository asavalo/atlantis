from typing import Optional, List

from pydantic import BaseModel
from python_aixcc_challenge.language.types import Language
from python_aixcc_challenge.detection.models import AIxCCChallengeMode
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as SarifReport,
)


class BlobInfo(BaseModel):
    harness_name: str
    sanitizer_name: str
    blob: bytes


class Detection(BaseModel):
    mode: Optional[AIxCCChallengeMode]
    vulnerability_identifier: str
    project_name: str
    language: Language  # This is necessary for crash analysis module
    blobs: List[BlobInfo] = []
    sarif_report: Optional[SarifReport] = None
