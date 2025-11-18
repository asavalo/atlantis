import os

import redis

from crs_sarif.models.models import (
    PatchMatchRequest,
    POVMatchRequest,
    SarifAnalysisResult,
    SARIFMatchRequest,
)
from crs_sarif.utils.decorator import singleton


@singleton
class RedisUtil:
    def __init__(self):
        self.redis = redis.Redis.from_url(
            os.getenv("CRS_SARIF_REDIS_URL", "redis://localhost:6379")
        )

    def set_pov_match_request(self, pov_obj: POVMatchRequest):
        self.redis.set(f"pov-match-request-{pov_obj.pov_id}", pov_obj.model_dump_json())

    def get_all_pov_match_requests(self) -> list[POVMatchRequest]:
        return [
            POVMatchRequest.model_validate_json(self.redis.get(key))
            for key in self.redis.keys("pov-match-request-*")
        ]

    def set_sarif_match_request(self, sarif_obj: SARIFMatchRequest):
        self.redis.set(
            f"sarif-match-request-{sarif_obj.sarif_id}", sarif_obj.model_dump_json()
        )

    def get_all_sarif_match_requests(self) -> list[SARIFMatchRequest]:
        return [
            SARIFMatchRequest.model_validate_json(self.redis.get(key))
            for key in self.redis.keys("sarif-match-request-*")
        ]

    def set_patch_match_request(self, patch_obj: PatchMatchRequest):
        self.redis.set(
            f"patch-match-request-{patch_obj.patch_id}", patch_obj.model_dump_json()
        )

    def get_all_patch_match_requests(self) -> list[PatchMatchRequest]:
        return [
            PatchMatchRequest.model_validate_json(self.redis.get(key))
            for key in self.redis.keys("patch-match-request-*")
        ]

    def set_sarif_analysis_result(self, sarif_analysis_result: SarifAnalysisResult):
        self.redis.set(
            f"sarif-analysis-result-{sarif_analysis_result.sarif_id}-{sarif_analysis_result.reachable_harness}",
            sarif_analysis_result.model_dump_json(),
        )

    def get_sarif_analysis_result(
        self, sarif_id: str, harness_name: str
    ) -> SarifAnalysisResult:
        raw_data = self.redis.get(f"sarif-analysis-result-{sarif_id}-{harness_name}")
        if raw_data is None:
            return None
        return SarifAnalysisResult.model_validate_json(raw_data)
