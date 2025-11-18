import asyncio
import inspect
from pathlib import Path

import urllib3
from loguru import logger
from pydantic import TypeAdapter

from crs_sarif.models.models import (
    SarifAnalysisResult,
    SARIFMatchRequest,
    SarifReachabilityResult,
)
from crs_sarif.utils.context import CRSEnv
from crs_sarif.utils.decorator import singleton
from crs_sarif.utils.redis_util import RedisUtil
from crs_sarif.utils.vapi_client import VapiClient
from sarif.context import SarifEnv
from sarif.models import (
    CodeLocation,
    ConfidenceLevel,
    Harness,
    Relations_C,
    Relations_Java,
)
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as AIxCCSarif,
)
from sarif.validator.preprocess.info_extraction import extract_essential_info
from sarif.validator.reachability.callgraph import CallGraph
from sarif.validator.reachability.codeql import CodeQLReachabilityAnalyser
from sarif.validator.reachability.sootup import SootupReachabilityAnalyser
from sarif.validator.reachability.svf import SVFReachabilityAnalyser

# CALLGRAPH_UPDATE_INTERVAL = 60 * 5
CALLGRAPH_UPDATE_INTERVAL = 60 * 3


async def run_task(update_function, interval):
    while True:
        try:
            func_name = getattr(update_function, "__name__", repr(update_function))
            if inspect.iscoroutinefunction(update_function):
                await update_function()
            else:
                await asyncio.to_thread(update_function)

            logger.info(f"Task {func_name} complete. Waiting for {interval} seconds...")
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            func_name = getattr(update_function, "__name__", repr(update_function))
            logger.info(f"Periodic task for {func_name} cancelled.")
            break
        except Exception:
            func_name = getattr(update_function, "__name__", repr(update_function))
            logger.exception(
                f"Error during task {func_name}. Retrying after {interval} seconds..."
            )
            await asyncio.sleep(interval)


@singleton
class AnalyserService:
    def __init__(
        self,
    ):
        self.main_analyser = CodeQLReachabilityAnalyser(cp=SarifEnv().cp)
        if (
            CRSEnv().project_language == "c"
            or CRSEnv().project_language == "cpp"
            or CRSEnv().project_language == "cpp"
        ):
            self.aux_analysers = [SVFReachabilityAnalyser(cp=SarifEnv().cp)]
        elif CRSEnv().project_language == "jvm" or CRSEnv().project_language == "java":
            self.aux_analysers = [
                SootupReachabilityAnalyser(
                    cp=SarifEnv().cp,
                    mode="cha",
                    cp_built_path=(CRSEnv().out_dir / CRSEnv().builder_out_dirname),
                    cp_src_path=CRSEnv().cp_src_path,
                )
            ]

        self._periodic_update_task = {
            "update_callgraphs": None,
        }
        self.update_interval = {
            "update_callgraphs": CALLGRAPH_UPDATE_INTERVAL,
        }
        self.processed_traces = set()

    async def init_callgraphs(self):
        logger.info(f"Initializing {self.main_analyser.name} callgraph")
        await asyncio.to_thread(self.main_analyser.init_callgraph)

    async def init_aux_callgraphs(self):
        for aux_analyser in self.aux_analysers:
            logger.info(f"Initializing {aux_analyser.name} callgraph")
            await asyncio.to_thread(aux_analyser.init_callgraph)

    async def merge_aux_callgraphs(self):
        for aux_analyser in self.aux_analysers:
            logger.info(
                f"Merging {self.main_analyser.name} and {aux_analyser.name} callgraphs"
            )
            await asyncio.to_thread(self.main_analyser.merge_callgraph, aux_analyser)

    def _get_reachable_harnesses(
        self, code_location: CodeLocation
    ) -> list[tuple[Harness, ConfidenceLevel]]:
        reachable_harnesses = self.main_analyser.get_reachable_harnesses(code_location)

        return reachable_harnesses

    def _get_target_callgraph(
        self, code_location: CodeLocation, harness: Harness, strong: bool = False
    ) -> CallGraph:
        callgraph = self.main_analyser.get_target_callgraph(
            code_location, harness, strong=strong
        )

        return callgraph

    async def get_analysis_result(
        self,
        sarif_obj: SARIFMatchRequest,
    ) -> list[SarifAnalysisResult]:
        sarif_model = AIxCCSarif.model_validate(sarif_obj.sarif)

        sarif_info = extract_essential_info(
            sarif_model,
            src_path=CRSEnv().cp_src_path,
            compiled_src_path=CRSEnv().compiled_src_dir,
            extract_func_name=True,
        )
        logger.info(f"SarifInfo: {sarif_info}")
        code_locations = sarif_info.code_locations

        sarif_reachability_results = dict()
        for code_location in code_locations:
            reachable_harnesses: list[tuple[Harness, ConfidenceLevel]] = (
                self._get_reachable_harnesses(code_location)
            )
            logger.info(f"Reachable Harnesses: {reachable_harnesses}")

            for harness, confidence_level in reachable_harnesses:
                # callgraph = self._get_target_callgraph(
                #     code_location, harness, strong=True
                # )
                callgraph = self._get_target_callgraph(
                    code_location,
                    harness,
                    strong=True if confidence_level == ConfidenceLevel.HIGH else False,
                )
                callgraph.print_stats()
                # For debugging
                # callgraph.dump_dot(
                #     Path(CRSEnv().reachability_shared_dir)
                #     / f"{harness.name}_sarif_analysis.dot"
                # )

                if harness.name not in sarif_reachability_results:
                    sarif_reachability_results[harness.name] = []

                sarif_reachability_results[harness.name].append(
                    SarifReachabilityResult(
                        code_location=code_location,
                        confidence_level=confidence_level,
                        callgraph=callgraph.to_json(),
                    )
                )

        sarif_analysis_results = []
        for harness_name, reachability_results in sarif_reachability_results.items():
            sarif_analysis_result = SarifAnalysisResult(
                sarif_id=sarif_obj.sarif_id,
                rule_id=sarif_info.ruleId,
                reachable_harness=harness_name,
                reachability_results=reachability_results,
            )
            # logger.info(
            #     f"SarifAnalysisResults: {sarif_analysis_result.model_dump_json()}"
            # )
            sarif_analysis_results.append(sarif_analysis_result)

        if len(sarif_analysis_results) == 0:
            logger.warning(
                f"No reachable harness found for sarif_id: {sarif_obj.sarif_id}, code_location: {code_locations}"
            )

        return sarif_analysis_results

    async def update_callgraphs(self):
        # CALL_TRACE_FILE_LIMIT = 100

        function_call_trace_dir = CRSEnv().call_trace_shared_dir
        all_files = sorted(
            function_call_trace_dir.glob("**/*.edges"),
            key=lambda x: x.stat().st_ctime,
            reverse=False,
        )
        # files = all_files[:CALL_TRACE_FILE_LIMIT]
        files = all_files

        logger.info(f"Found {len(all_files)} trace files in {function_call_trace_dir}")

        if CRSEnv().project_language == "c":
            relations_adapter = TypeAdapter(Relations_C)
        elif CRSEnv().project_language == "jvm":
            relations_adapter = TypeAdapter(Relations_Java)

        new_traces_processed = 0
        new_relations: list[Relations_C | Relations_Java] = []

        for file in files:
            harness_name = file.as_posix().split("/")[-2]

            file_path_str = str(file)
            if file_path_str in self.processed_traces:
                continue

            try:
                with open(file, "r") as f:
                    relations_data = relations_adapter.validate_json(f.read())
                    if CRSEnv().project_language in ["c", "cpp", "c++"]:
                        for relation in relations_data:
                            relation.harness_name = harness_name

                new_relations.append(relations_data)

                self.processed_traces.add(file_path_str)
                new_traces_processed += 1

            except Exception as e:
                logger.exception(f"Error processing trace file {file}: {e}")

        logger.info(
            f"Found {new_traces_processed} new relations in {function_call_trace_dir}"
        )

        updated_edges = 0
        if new_relations:
            updated_edges = await asyncio.to_thread(
                self.main_analyser.update_callgraph_batch, new_relations
            )

        if new_traces_processed > 0:
            logger.info(
                f"Processed {new_traces_processed} new trace files for callgraph update."
            )
            logger.info(f"Updated {updated_edges} edges.")
        else:
            logger.debug("No new trace files found for callgraph update.")

        if updated_edges > 0:
            logger.info(
                "Call graph has been updated. Dump new call graphs and regenerate SarifAnalysisResult"
            )
            await self.dump_reachability_results()
            await self.update_analysis_results()

        # remove files
        for file in files:
            file.unlink()

        logger.debug(f"Removed {len(files)} files after updating callgraphs")

    async def update_analysis_results(self):
        sarif_match_requests = RedisUtil().get_all_sarif_match_requests()

        for sarif_match_request in sarif_match_requests:
            sarif_analysis_results = await self.get_analysis_result(sarif_match_request)

            for sarif_analysis_result in sarif_analysis_results:
                old_sarif_analysis_result = RedisUtil().get_sarif_analysis_result(
                    sarif_analysis_result.sarif_id,
                    sarif_analysis_result.reachable_harness,
                )

                if old_sarif_analysis_result is not None:
                    if (
                        old_sarif_analysis_result.reachability_results
                        == sarif_analysis_result.reachability_results
                    ):
                        logger.info(
                            "SarifAnalysisResult is the same as the old one. Skip to send."
                        )
                        continue
                    else:
                        logger.info(
                            f"SarifAnalysisResult has been updated. Send it to VAPI. sarif_id: {sarif_analysis_result.sarif_id}, reachable_harness: {sarif_analysis_result.reachable_harness}"
                        )

                self.broadcast_analysis_result(sarif_analysis_result)

    def broadcast_analysis_result(self, analysis_result: SarifAnalysisResult):
        RedisUtil().set_sarif_analysis_result(analysis_result)

        try:
            VapiClient().broadcast_sarif_analysis(
                str(analysis_result.sarif_id), analysis_result
            )
        except urllib3.exceptions.MaxRetryError as e:
            logger.exception(f"Error sending analysis results to VAPI: {e}")

    async def dump_reachability_results(self):
        logger.info("Removing existing reachability results...")

        # Run file removal in thread executor
        await asyncio.to_thread(self._remove_existing_results)

        logger.info("Dumping reachability results...")
        # Run dump operation in thread executor
        await asyncio.to_thread(
            lambda: self.main_analyser.dump_all_callgraphs(format="json")
        )
        logger.info("Reachability results dumped.")

    def _remove_existing_results(self):
        for file in CRSEnv().reachability_shared_dir.iterdir():
            if file.is_file():
                file.unlink()

    async def start_tasks(self):
        logger.info("Starting tasks...")
        for update_function in self._periodic_update_task:
            await self._start_periodic_task(
                update_function, self.update_interval[update_function]
            )
        logger.info("Tasks started.")

    async def stop_tasks(self):
        logger.info("Stopping tasks...")
        for update_function in self._periodic_update_task:
            await self._stop_periodic_task(update_function)
        logger.info("Tasks stopped.")

    async def _start_periodic_task(self, update_function, interval):
        try:
            method_to_run = getattr(self, update_function)
        except AttributeError:
            logger.error(f"Cannot find method {update_function} in AnalyserService.")
            return

        if (
            self._periodic_update_task.get(update_function) is None
            or self._periodic_update_task[update_function].done()
        ):
            logger.info(
                f"Starting periodic {update_function} every {self.update_interval[update_function]} seconds."
            )
            self._periodic_update_task[update_function] = asyncio.create_task(
                run_task(method_to_run, interval)
            )
        else:
            logger.warning(f"Periodic {update_function} task already running.")

    async def _stop_periodic_task(self, update_function):
        if self._periodic_update_task[update_function] is not None:
            self._periodic_update_task[update_function].cancel()
            self._periodic_update_task[update_function] = None
        else:
            logger.warning(f"Periodic {update_function} task already stopped.")
