from os.path import basename
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from langchain_core.messages import SystemMessage
from python_llm.api.actors import LlmApiManager

from crete.atoms.action import NoPatchAction
from crete.atoms.detection import Detection
from crete.commons.interaction.exceptions import CommandInteractionError
from crete.commons.interaction.functions import run_command
from crete.framework.agent.services.vincent.code_inspector import VincentCodeInspector
from crete.framework.agent.services.vincent.code_inspector.models import CodeQueryResult
from crete.framework.agent.services.vincent.functions import (
    create_prompt,
    filter_crash_log,
    send_and_update_llm,
)
from crete.framework.agent.services.vincent.nodes.llm_node import LLMNode
from crete.framework.agent.services.vincent.nodes.requests.functions import (
    aggregate_code_query_results,
)
from crete.framework.agent.services.vincent.states.patch_state import (
    PatchStage,
    PatchState,
)
from crete.framework.environment.exceptions import ChallengePoVFoundError
from crete.framework.fault_localizer.models import FaultLocation
from crete.framework.fault_localizer.services.sarif import SarifFaultLocalizer

MAX_BLOB_SIZE = 25000  # about 50,000 tokens


class InitAnalyzer(LLMNode):
    def __init__(self, llm_api_manager: LlmApiManager):
        super().__init__(llm_api_manager)
        self.code_inspector: VincentCodeInspector | None = None

    def __call__(self, state: PatchState) -> dict[str, Any]:
        assert state.patch_stage == PatchStage.INIT_ANALYSIS
        assert self.context is not None
        assert state.detection is not None

        system_prompt = create_prompt("vincent_system_prompt")
        state.messages.append(SystemMessage(system_prompt))

        init_prompt = self._get_proper_init_prompt(state)

        if init_prompt is None:
            state.action = NoPatchAction()
            state.patch_stage = PatchStage.DONE
            return self._get_dict_from_state(state)

        send_and_update_llm(
            self.context,
            state.messages,
            self.llm,
            init_prompt,
        )

        # First step is to analyze the root cause of the given bug.
        state.patch_stage = PatchStage.ANALYZE_ROOT_CAUSE
        state.action = NoPatchAction()
        return self._get_dict_from_state(state)

    def set_code_inspector(self, code_inspector: VincentCodeInspector):
        self.code_inspector = code_inspector

    def _get_crash_log(self, detection: Detection) -> str | None:
        environment = self.context["pool"].restore(self.context)
        try:
            environment.run_pov(self.context, detection)
            raise RuntimeError(f"Crash not occurred for the detection {detection}.")
        except ChallengePoVFoundError as e:
            return filter_crash_log(
                e.stdout.decode(errors="replace"), self.context, detection
            )

    def _get_proper_init_prompt(self, state: PatchState) -> str | None:
        assert state.detection is not None

        crash_log = None
        sarif_report = None

        input_xxd_result = ""
        if len(state.detection.blobs) != 0:
            crash_log = self._get_crash_log(state.detection)
            if crash_log is None:
                self.context["logger"].error("Sanitizer report pattern was not found")
                return None

            input_xxd_result = self._get_input_text_with_xxd(state.detection)

        if state.detection.sarif_report is not None:
            sarif_report = self._make_sarif_report(state.detection)

        if crash_log is not None and sarif_report is not None:
            return create_prompt(
                "init_analyzer_init_crash_and_sarif",
                input_args={
                    "PROJ_NAME": basename(state.detection.project_name),
                    "SANITIZER_REPORT": crash_log,
                    "SARIF_REPORT": sarif_report,
                    "INPUT_XXD": input_xxd_result,
                },
            )
        elif crash_log is not None and sarif_report is None:
            return create_prompt(
                "init_analyzer_init_crash_only",
                input_args={
                    "PROJ_NAME": basename(state.detection.project_name),
                    "SANITIZER_REPORT": crash_log,
                    "INPUT_XXD": input_xxd_result,
                },
            )
        elif crash_log is None and sarif_report is not None:
            return create_prompt(
                "init_analyzer_init_sarif_only",
                input_args={
                    "PROJ_NAME": basename(state.detection.project_name),
                    "SARIF_REPORT": sarif_report,
                },
            )
        else:
            return None

    def _make_sarif_report(self, detection: Detection) -> str | None:
        assert detection.sarif_report is not None, "Sarif report is None"
        assert self.code_inspector is not None

        sarif_result = SarifFaultLocalizer().localize(self.context, detection)

        sarif_report_str = ""
        if sarif_result.description:
            sarif_report_str += f"* Description:\n{sarif_result.description}\n"

        buggy_snippets: list[CodeQueryResult] = []
        for i, fault_location in enumerate(sarif_result.locations):
            sarif_report_str += f"* Bug location {i + 1}:\n"
            sarif_report_str += f" - File: {fault_location.file}\n"
            if fault_location.line_range:
                sarif_report_str += f" - Line range: {fault_location.line_range}\n"
            if fault_location.function_name:
                sarif_report_str += (
                    f" - Function name: `{fault_location.function_name}`\n"
                )

            cur_fault_snippets = self._get_snippets_from_sarif_location(fault_location)

            if cur_fault_snippets is None:
                return None

            buggy_snippets += cur_fault_snippets

        if len(buggy_snippets) == 0:
            self.context["logger"].error("No valid snippet for sarif report found...")
            return None

        sarif_report_str += "* Related code snippets:\n\n"
        sarif_report_str += aggregate_code_query_results("", buggy_snippets)

        return sarif_report_str

    def _get_snippets_from_sarif_location(
        self, fault_location: FaultLocation
    ) -> list[CodeQueryResult] | None:
        assert self.code_inspector is not None

        if fault_location.line_range is None:
            self.context["logger"].warning("No line range found in sarif report..")
            return None

        # @NOTE: there are cases that sarif report are relative paths, not absolute paths. (e.g., nginx cpv-6)
        if not fault_location.file.is_absolute():
            fault_abs_src_path = (
                self.context["pool"].source_directory / fault_location.file
            )
        else:
            fault_abs_src_path = fault_location.file

        if not fault_abs_src_path.exists():
            self.context["logger"].warning(
                f"source path `{fault_abs_src_path}` from sarif report does not exist"
            )
            return None

        # @NOTE: sometimes `fault_location.line_range[1]` points to the outside of the function frame (e.g., `custom-c-r2-sqlite3-cpv-1-sarif-only.toml`)
        # Is it guaranteed that the fault_location.line_range resides within the function body?
        tag_entry = self.code_inspector.ctags_parser.get_entry_at_line(
            fault_abs_src_path,
            min(
                fault_location.line_range[0] + 3, fault_location.line_range[1]
            ),  # ensure this line indicates the middle of problematic function body.
        )

        if tag_entry is None:
            self.context["logger"].warning(
                f"ctags entry not found for `{fault_abs_src_path}` (line range: {fault_location.line_range[0]}-{fault_location.line_range[1]})"
            )
            return None

        query_results = self.code_inspector.get_definition(tag_entry.name)
        if query_results is None:
            self.context["logger"].warning(
                f"Failed to get snippet of `{tag_entry.name}` specified in sarif report..."
            )
            return None

        results: list[CodeQueryResult] = []
        # Double check query result is same with fault_location.
        for result in query_results:
            if result.abs_src_path != fault_abs_src_path:
                continue
            results.append(result)

        if len(results) == 0:
            return None

        return results

    def _get_input_text_with_xxd(self, detection: Detection) -> str:
        if len(detection.blobs[0].blob) > MAX_BLOB_SIZE:
            self.context["logger"].info(
                f"blob filesize exceeds {MAX_BLOB_SIZE} (size: {len(detection.blobs[0].blob)})."
            )
            return ""

        with NamedTemporaryFile() as f:
            f.write(detection.blobs[0].blob)
            f.flush()

            try:
                stdout, _ = run_command((f"xxd {f.name}", Path(".")))
            except CommandInteractionError:
                self.context["logger"].warning(
                    "running xxd on crashing input failed..."
                )
                return ""

            return f"The xxd utility's ouput on the crashing input is as below.\n\n* xxd output:\n```\n{stdout}```\n"
