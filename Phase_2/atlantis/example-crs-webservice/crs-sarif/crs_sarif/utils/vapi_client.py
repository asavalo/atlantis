import json
import logging
import os
from typing import Literal
from uuid import UUID

import openapi_client as vapi_client

from crs_sarif.models.models import SarifAnalysisResult, SARIFMatchRequest
from crs_sarif.utils.decorator import singleton

logger = logging.getLogger(__name__)


@singleton
class VapiClient:
    def __init__(self):
        self.configuration = vapi_client.Configuration(host=os.getenv("VAPI_HOST"))
        self.api_client = vapi_client.ApiClient(self.configuration)
        self.api_instance = vapi_client.DefaultApi(self.api_client)

    def broadcast_sarif_analysis(
        self, sarif_id: UUID, sarif_analysis: SarifAnalysisResult, dump_res: bool = True
    ):
        logger.info(f"Send analysis results to VAPI /broadcast/sarif")
        if dump_res:
            with open(
                f"sarif_analysis-{sarif_analysis.reachable_harness}.json", "w"
            ) as f:
                json.dump(sarif_analysis.model_dump(mode="json"), f)

        payload = vapi_client.TypesSarifAssessmentBroadcast(
            sarif_id=sarif_id,
            fuzzer_name=sarif_analysis.reachable_harness,
            analysis_result=sarif_analysis.model_dump(mode="json"),
        )

        if dump_res:
            with open(
                f"sarif_broadcast-{sarif_analysis.reachable_harness}.json", "w"
            ) as f:
                json.dump(payload.model_dump(mode="json"), f)

        self.api_instance.broadcast_sarif_post(payload)

    def submit_sarif(
        self,
        assessment: Literal["correct", "incorrect"],
        sarif_id: UUID,
        pov_id: UUID,
        description: str,
    ):
        logger.info(f"Submit sarif to VAPI /submit/sarif")
        payload = vapi_client.TypesSarifAssessmentSubmission(
            assessment=assessment,
            sarif_id=sarif_id,
            pov_id=pov_id,
            description=description,
        )
        self.api_instance.submit_sarif_post(payload)
