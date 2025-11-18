import asyncio
import base64
import logging
import os
from typing import Callable, Optional, TypeAlias
from uuid import UUID

import requests
from crs_patch.models import PatchRequest, SubmissionStatus
from crs_patch.protocols import SubmitterProtocol
from pydantic import BaseModel

PATCH_ID: TypeAlias = UUID
POV_ID: TypeAlias = UUID


class Submission(BaseModel):
    pov_id: POV_ID
    patch_id: PATCH_ID


class Submitter(SubmitterProtocol):
    def __init__(self, vapi_host: str = os.environ["VAPI_HOST"]):
        self.vapi_host = vapi_host
        self.logger = logging.getLogger(__name__)
        self.status: dict[POV_ID, SubmissionStatus] = {}
        self.submission_queue: asyncio.Queue[Submission] = asyncio.Queue()
        self.callbacks: list[Callable[[POV_ID, SubmissionStatus], None]] = []

    def submit(
        self, request: PatchRequest, patch: str, patched_again_pov_ids: list[UUID]
    ) -> None:
        vapi_url = f"{self.vapi_host}/submit/patch/pov/{request.pov_id}"

        b64encoded_patch = base64.b64encode(patch.encode()).decode()
        self.logger.info(f"Submitting patch to VAPI: {vapi_url}")
        response = requests.post(
            vapi_url,
            json={
                "patched_again_pov_ids": [
                    str(pov_id) for pov_id in patched_again_pov_ids
                ],
                "patch": b64encoded_patch,
            },
        )

        self.logger.info(f"VAPI response status: {response.status_code}")
        if response.status_code != 200:
            self.logger.error(f"VAPI response: {response.text}")
            raise Exception(f"VAPI response: {response.text}")

        response_json = response.json()
        self.logger.info(f"VAPI response: {response_json}")

        patch_id = response_json["patch_id"]
        self.logger.info(f"Patch ID: {patch_id}")
        self.submission_queue.put_nowait(
            Submission(pov_id=request.pov_id, patch_id=patch_id)
        )
        self.status[request.pov_id] = SubmissionStatus.accepted

    def register_callback(
        self, callback: Callable[[POV_ID, SubmissionStatus], None]
    ) -> None:
        self.callbacks.append(callback)

    async def handle_submit_result(self) -> None:
        while True:
            submission = await self.submission_queue.get()

            status = await asyncio.to_thread(
                self._get_submit_status, submission.patch_id
            )

            if status is not None and self._update_status(submission.pov_id, status):
                for callback in self.callbacks:
                    callback(submission.pov_id, status)
                self.submission_queue.task_done()
            else:
                await self.submission_queue.put(submission)

            await asyncio.sleep(3)

    def _get_submit_status(self, patch_id: PATCH_ID) -> Optional[SubmissionStatus]:
        vapi_url = f"{self.vapi_host}/submit/patch/{patch_id}"
        try:
            response = requests.get(vapi_url)
            response_json = response.json()
            self.logger.info(f"VAPI response: {response_json}")

            return SubmissionStatus(response_json["status"])

        except Exception as e:
            self.logger.error(f"Error requesting status from VAPI: {e}")
            return None

    def _update_status(
        self, pov_id: POV_ID, status: Optional[SubmissionStatus]
    ) -> bool:
        if status is None:
            return False

        match status:
            case SubmissionStatus.accepted:
                return False
            case _:
                self.status[pov_id] = status
                return True

    def get_status(self, pov_id: POV_ID) -> Optional[SubmissionStatus]:
        return self.status.get(pov_id)
