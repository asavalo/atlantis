import logging
import os
import time
import traceback
from pathlib import Path
from typing import List, Optional

from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.crete import Crete
from crs_patch.models import PatchRequest
from crs_patch.protocols import PatcherProtocol
from crs_patch.utils.challenges import construct_challenge_mode
from python_aixcc_challenge.detection.models import AIxCCChallengeProjectDetection

from scripts.benchmark.functions import execute_in_process, tracking_llm_cost
from scripts.benchmark.models import BenchmarkResult

logger = logging.getLogger(__name__)


class CretePatcher(PatcherProtocol):
    def __init__(
        self,
        challenge_project_directory: Path,
        output_directory: Path,
        cache_directory: Path,
        apps: List[Crete],
    ):
        self.challenge_project_directory = challenge_project_directory
        self.output_directory = output_directory
        self.cache_directory = cache_directory
        self.apps = apps

        self.timeout = 30 * 60  # 30 minutes
        self.llm_cost_limit = 10.0

    def patch(self, request: PatchRequest) -> Optional[str]:
        logger.info(f"Start patching: {request.pov_id}")

        output_directory = self.output_directory / str(request.pov_id)
        os.makedirs(output_directory, exist_ok=True)

        detection_toml_file = output_directory / f"{request.pov_id}.toml"

        with open(detection_toml_file, "w") as fp:
            detection_toml = AIxCCChallengeProjectDetection.model_validate(
                {
                    "vulnerability_identifier": str(request.pov_id),
                    "project_name": request.project_name,
                    "blobs": [blob.to_challenge_blob_info() for blob in request.blobs],
                    "sarif_report": request.sarif_report,
                    "mode": construct_challenge_mode(
                        self.challenge_project_directory, request.type.value
                    ),
                }
            )
            fp.write(detection_toml.to_toml())

        for app in self.apps:
            logger.info(f"Running app: {app.id}")
            try:
                crete_result, benchmark_json = execute_in_process(
                    _run_app,
                    (
                        app,
                        self.challenge_project_directory,
                        detection_toml_file,
                        output_directory,
                        self.cache_directory,
                        self.timeout,
                        self.llm_cost_limit,
                    ),
                    timeout=self.timeout + 30,  # Add 30 seconds for overhead
                )
                logger.info(f"App {app.id} result: {crete_result}")
                (output_directory / f"{app.id}.json").write_text(
                    benchmark_json.model_dump_json()
                )

                match benchmark_json:
                    case BenchmarkResult(variant="sound"):
                        return crete_result.diff
                    case _:
                        continue
            except TimeoutError:
                logger.error(f"App {app.id} timed out", exc_info=True)
                continue
            except Exception as e:
                logger.error(f"Error running app {app.id}: {e}", exc_info=True)
                continue

        # Failed to generate patch
        logger.info(f"Failed to generate patch for {request.pov_id}")
        return None


def _run_app(
    app: Crete,
    challenge_project_directory: Path,
    detection_toml_file: Path,
    output_directory: Path,
    cache_directory: Path,
    timeout: int,
    llm_cost_limit: float,
):
    start_time = time.time()
    llm_cost = 0

    def _update_llm_cost(cost: float):
        nonlocal llm_cost
        llm_cost += cost

    try:
        with tracking_llm_cost(_update_llm_cost):
            crete_result = app.run(
                context_builder=AIxCCContextBuilder(
                    challenge_project_directory=challenge_project_directory,
                    detection_toml_file=detection_toml_file,
                    output_directory=output_directory,
                    cache_directory=cache_directory,
                    logging_level=logging.DEBUG,
                ),
                timeout=timeout,
                llm_cost_limit=llm_cost_limit,
                output_directory=output_directory,
            )

        elapsed_time = int(time.time() - start_time)

        logger.info(f"App {app.id} finished in {elapsed_time} seconds")
        logger.info(f"LLM cost: {llm_cost}")
        return crete_result, BenchmarkResult.from_crete_result(
            crete_result,
            detection_toml_file.stem,
            elapsed_time,
            llm_cost,
        )
    except Exception as e:
        logger.error(f"Error running app {app.id}: {e}", exc_info=True)

        elapsed_time = int(time.time() - start_time)

        logger.info(f"App {app.id} finished in {elapsed_time} seconds")
        logger.info(f"LLM cost: {llm_cost}")
        return None, BenchmarkResult.model_validate(
            {
                "cpv_name": detection_toml_file.stem,
                "variant": "unknown_error",
                "message": traceback.format_exc(),
                "elapsed_time": elapsed_time,
                "llm_cost": llm_cost,
            }
        )
