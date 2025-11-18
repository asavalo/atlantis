import asyncio
import logging
import time
from pathlib import Path
from typing import List, Optional
from uuid import UUID

import requests
from crete.framework.crete import Crete
from crs_patch.models import Config, PatchRequest, PatchStatus, Status, SubmissionStatus
from crs_patch.protocols import RequestHandlerProtocol, SubmitterProtocol
from crs_patch.services.patch_checker import PatchChecker
from crs_patch.services.patch_manager import PatchManager
from crs_patch.services.patcher import CretePatcher
from crs_patch.services.scheduler import RoundRobinScheduler
from pydantic import BaseModel

SLEEP_TIME = 10


class RequestHandler(RequestHandlerProtocol):
    class PatchRecord(BaseModel):
        patch_request: PatchRequest
        retries: int = 0

    def __init__(
        self,
        task_id: str,
        subconfigs: List[Config],
        patch_manager: PatchManager,
        submitter: SubmitterProtocol,
    ):
        self.task_id = task_id
        self.queue: asyncio.Queue[PatchRequest] = asyncio.Queue()
        self.subconfigs = subconfigs
        self.patch_manager = patch_manager
        self.submitter = submitter
        self.logger = logging.getLogger(__name__)
        self.requests: dict[UUID, RequestHandler.PatchRecord] = {}
        self.status: dict[UUID, PatchStatus] = {}

    async def put(self, request: PatchRequest) -> None:
        if request.pov_id in self.requests:
            self.requests[request.pov_id].retries += 1
        else:
            self.requests[request.pov_id] = RequestHandler.PatchRecord(
                patch_request=request
            )

        self.logger.info(
            f"Queueing request: {request.pov_id} with trial {self.requests[request.pov_id].retries}"
        )
        self.status[request.pov_id] = PatchStatus(
            pov_id=request.pov_id, status=Status.waiting, patch_diff=None
        )
        await self.queue.put(request)

    async def handle(self) -> None:
        while True:
            request = await self.queue.get()
            assert request is not None

            self.logger.info(f"Processing request: {request.pov_id}")
            self.status[request.pov_id].status = Status.processing

            if await asyncio.to_thread(self.patch_manager.is_pov_blocked, request):
                self.status[request.pov_id].status = Status.succeeded
                self.logger.info(f"POV is already blocked: {request.pov_id}")
                self.queue.task_done()
                continue

            try:
                result = await asyncio.to_thread(self.deploy, request)

                if result is None:
                    self.status[request.pov_id].status = Status.failed
                    self.logger.info(f"Failed to patch request: {request.pov_id}")
                else:
                    self.logger.info(f"Succeeded to patch request: {request.pov_id}")
                    self.logger.info(f"Generated patch: {result}")

                    if await asyncio.to_thread(
                        self.patch_manager.is_pov_blocked, request
                    ):
                        self.status[request.pov_id].status = Status.succeeded
                        self.logger.info(f"POV is already blocked: {request.pov_id}")
                        self.queue.task_done()
                        continue

                    self.status[request.pov_id].status = Status.succeeded

                    patched_again_pov_ids = self.patch_manager.add_patch(
                        result, request
                    )
                    await asyncio.to_thread(
                        self.submitter.submit, request, result, patched_again_pov_ids
                    )
            except Exception as e:
                self.status[request.pov_id].status = Status.errored
                self.logger.error(
                    f"Error occurred while patching request: {request.pov_id}"
                )
                self.logger.error(f"Error: {e}", exc_info=True)

            self.queue.task_done()

    def get_subnode_url(self, subconfig: Config) -> str:
        return f"http://crs-patch-sub-{subconfig.id}-{self.task_id}"

    def deploy(self, request: PatchRequest) -> Optional[str]:
        try:
            for app_config in self.subconfigs:
                response = requests.post(
                    f"{self.get_subnode_url(app_config)}/v1/patch/",
                    headers={"Content-Type": "application/json"},
                    data=request.model_dump_json(),
                )
                if response.status_code != 200:
                    self.logger.error(
                        f"Failed to deploy request: {request.pov_id} to {app_config.id}"
                    )

            subconfigs = self.subconfigs[:]
            while subconfigs:
                for app_config in subconfigs:
                    response = requests.get(
                        f"{self.get_subnode_url(app_config)}/v1/patch/{request.pov_id}/"
                    )
                    if response.status_code != 200:
                        self.logger.error(
                            f"Failed to get patch status: {request.pov_id} from {app_config.id}"
                        )

                    response_json = response.json()
                    if response_json["status"] == "succeeded":
                        return response_json["patch_diff"]

                    elif (
                        response_json["status"] == "failed"
                        or response_json["status"] == "errored"
                    ):
                        subconfigs.remove(app_config)
                time.sleep(SLEEP_TIME)

            self.logger.info(
                f"All sub-systems failed to patch for request: {request.pov_id}"
            )
            return None

        except requests.RequestException as e:
            self.logger.error(
                f"Error occurred while deploying request: {request.pov_id}"
            )
            self.logger.error(f"Error: {e}", exc_info=True)
            return None

    def handle_submission_callback(self, pov_id: UUID, status: SubmissionStatus):
        if status == SubmissionStatus.failed:
            if self.requests[pov_id].retries >= 2:
                self.logger.info(f"Max retries reached for request: {pov_id}")
                return
            try:
                loop = asyncio.get_event_loop()
                loop.create_task(self.put(self.requests[pov_id].patch_request))
            except RuntimeError:
                self.logger.error(
                    f"Failed to handle submission callback: {pov_id}, {status}"
                )

    def get_status(self, pov_id: UUID) -> Optional[PatchStatus]:
        return self.status.get(pov_id)


class RoundRobinHandler(RequestHandlerProtocol):
    class Runner(BaseModel):
        patcher: CretePatcher
        request: PatchRequest

        class Config:
            arbitrary_types_allowed = True

    def __init__(
        self,
        challenge_project_directory: Path,
        output_directory: Path,
        cache_directory: Path,
        patch_checker: PatchChecker,
        apps: List[Crete],
    ):
        self.scheduler = RoundRobinScheduler[UUID, RoundRobinHandler.Runner](
            preserve_mode=False
        )
        self.patchers = [
            CretePatcher(
                challenge_project_directory,
                output_directory,
                cache_directory,
                apps=[app],
            )
            for app in apps
        ]
        self.patch_checker = patch_checker
        self.logger = logging.getLogger(__name__)
        self.status: dict[UUID, PatchStatus] = {}

    async def put(self, request: PatchRequest) -> None:
        self.logger.info(f"Queueing request: {request.pov_id}")
        runners = [
            RoundRobinHandler.Runner(patcher=patcher, request=request)
            for patcher in self.patchers
        ]
        self.scheduler.put(request.pov_id, runners)
        self.status[request.pov_id] = PatchStatus(
            pov_id=request.pov_id, status=Status.waiting, patch_diff=None
        )
        self.logger.info(f"Queueing length: {len(self.scheduler.task_queue_order)}")

    async def handle(self) -> None:
        while True:
            await asyncio.sleep(1)
            pov_id = self.scheduler.get_next_task()
            if not pov_id:
                continue

            if self._is_done(pov_id):
                continue

            runner = self.scheduler.get_next_runner(pov_id)
            if not runner:
                continue

            patcher_ids = [app.id for app in runner.patcher.apps]

            self.logger.info(
                f"Processing request: {pov_id} with patcher: {patcher_ids}"
            )
            self.status[pov_id].status = Status.processing

            result = await self.process_runner(runner)
            self.logger.info(f"Generated patch: {result}")

            if result is not None:
                try:
                    await asyncio.to_thread(
                        self.patch_checker.check, result, runner.request
                    )
                except Exception as e:
                    self.logger.error(f"Failed to check patch for request: {pov_id}")
                    self.logger.error(f"Error: {e}", exc_info=True)
                    result = None

            self.handle_runner_result(pov_id, result)

    def handle_runner_result(self, pov_id: UUID, result: Optional[str]):
        """Handle the result of a runner execution."""
        if result is not None:
            self.logger.info(f"Succeeded to patch request: {pov_id}")
            self.status[pov_id].status = Status.succeeded
            self.status[pov_id].patch_diff = result
            self.scheduler.remove_task(pov_id)
        elif not self.scheduler.task_queues.get(pov_id):
            self.status[pov_id].status = Status.failed
            self.logger.info(f"All apps failed for request: {pov_id}")
            self.scheduler.remove_task(pov_id)

    async def process_runner(self, runner: Runner) -> Optional[str]:
        """Process a single runner and return its result."""
        try:
            result = await asyncio.to_thread(runner.patcher.patch, runner.request)
            return result

        except Exception as e:
            self.logger.error(f"Error processing runner: {e}", exc_info=True)
            return None

    def get_status(self, pov_id: UUID) -> Optional[PatchStatus]:
        return self.status.get(pov_id)

    def _is_done(self, pov_id: UUID) -> bool:
        return (
            self.status[pov_id].status == Status.failed
            or self.status[pov_id].status == Status.succeeded
        )
