import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from python_aixcc_challenge.language.types import Language
from python_llm.api.actors import LlmApiManager
from unidiff import PatchSet

from crete.atoms.action import (
    Action,
    CompilableDiffAction,
    NoPatchAction,
    VulnerableDiffAction,
    choose_best_action,
)
from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.functions import store_debug_file
from crete.framework.agent.protocols import AgentProtocol
from crete.framework.coder.services.minimal import MinimalCoder
from crete.framework.fault_localizer.models import FaultLocation
from crete.framework.fault_localizer.services.coderover_k import (
    CodeRoverKFaultLocalizer,
    FeedbackRecord,
    NoPatchReason,
)
from crete.framework.insighter.services.module_imports import ModuleImportsInsighter


@dataclass
class PatchingState:
    # Store feedback for the fault localizer when patches are vulnerable or compilable but incorrect.
    # For other action types, no feedback is needed since they indicate different issues.
    rover_feedback: FeedbackRecord | None = None

    # Enabled when the uncompilable patch is generated.
    # Once enabled, it will be disabled the next time.
    skip_fault_localization: bool = False

    # Enabled when the uncompilable patch is generated.
    # Once enabled, it remains enabled.
    use_imports_insight: bool = False

    # Number of total iterations
    iteration: int = 0

    def update(
        self,
        action: Action,
        fault_location: FaultLocation | None = None,
        report: str | None = None,
        no_patch_reason: NoPatchReason | None = None,
    ) -> bool:
        """
        Returns True if the agent should stop.
        """
        self._update_rover_feedback(action, fault_location, report, no_patch_reason)
        self._update_skip_fault_localization(action)
        self._update_use_imports_insight(action)
        self.iteration += 1
        return action.variant in ("sound", "unknown_error", "head")

    def _update_rover_feedback(
        self,
        action: Action,
        fault_location: FaultLocation | None,
        report: str | None,
        no_patch_reason: NoPatchReason | None,
    ) -> None:
        if (
            action.variant in ("vulnerable", "compilable", "no_patch")
            and fault_location
            and report
        ):
            assert isinstance(
                action,
                VulnerableDiffAction | CompilableDiffAction | NoPatchAction,
            )
            self.rover_feedback = FeedbackRecord(
                action=action,
                fault_location=fault_location,
                report=report,
                no_patch_reason=no_patch_reason,
            )
        else:
            self.rover_feedback = None

    def _update_skip_fault_localization(self, action: Action) -> None:
        if action.variant == "uncompilable" and not self.skip_fault_localization:
            self.skip_fault_localization = True
        else:
            self.skip_fault_localization = False

    def _update_use_imports_insight(self, action: Action) -> None:
        if action.variant == "uncompilable":
            self.use_imports_insight = True
        else:
            self.use_imports_insight = False


class Workflow:
    def __init__(
        self,
        fault_localization_llm: LlmApiManager,
        report_parser_llm: LlmApiManager,
        code_generation_llm: LlmApiManager,
        max_iterations: int,
        output_dir: Path | None = None,
        backup_llm: LlmApiManager | None = None,
    ):
        self._fault_localization_llm = fault_localization_llm
        self._report_parser_llm = report_parser_llm
        self._code_generation_llm = code_generation_llm
        self._backup_llm = backup_llm
        self._max_iterations = max_iterations
        self._output_dir = output_dir

    def run(self, context: AgentContext, detection: Detection) -> Iterator[Action]:
        """
        Iteratively generate and evaluate patches:
        1. Localize fault (could be skipped)
        2. Generate patch
        3. Evaluate patch
        """
        rover = CodeRoverKFaultLocalizer(
            self._fault_localization_llm,
            self._report_parser_llm,
        )
        state = PatchingState()
        fault_location: FaultLocation | None = None
        actions: list[Action] = []

        while state.iteration < self._max_iterations:
            _set_agent_output_directory(context, self._output_dir, state.iteration)

            # Localize fault if needed
            if not state.skip_fault_localization:
                fault_locations = rover.localize(
                    context, detection, state.rover_feedback
                ).locations
                if len(fault_locations) == 0:
                    context["logger"].warning("No fault location found")
                    state.update(NoPatchAction(), no_patch_reason=NoPatchReason.OTHER)
                    continue
                assert len(fault_locations) == 1, (
                    "CodeRoverK only supports single-hunk fault localization"
                )
                fault_location = fault_locations[0]
            assert fault_location is not None
            store_debug_file(context, "fault_location.txt", str(fault_location))
            if _is_harness_file(fault_location.file, context["pool"].source_directory):
                context["logger"].warning("CodeRoverK localized a harness file")
                state.update(
                    NoPatchAction(),
                    fault_location,
                    rover.final_report,
                    NoPatchReason.HARNESS_FILE_LOCALIZED,
                )
                continue

            # Generate patch
            imports_insight = (
                ModuleImportsInsighter(fault_location.file).create(context, detection)
                if state.use_imports_insight
                else None
            )
            prompt = _make_prompt(
                context,
                fault_location,
                rover.final_report,
                detection.language,
                imports_insight,
            )
            store_debug_file(context, "prompt.txt", prompt)
            environment = context["pool"].use(context, "CLEAN")
            assert environment is not None
            diff = MinimalCoder(
                context,
                detection,
                environment,
                self._code_generation_llm,
                fault_location,
                self._backup_llm,
            ).run(context, prompt)
            if diff is None:
                context["logger"].warning("No diff found")
                state.update(
                    NoPatchAction(),
                    fault_location,
                    rover.final_report,
                    NoPatchReason.OTHER,
                )
                continue
            if _is_fuzzer_specific_patch(diff.decode(errors="replace")):
                state.update(
                    NoPatchAction(),
                    fault_location,
                    rover.final_report,
                    NoPatchReason.FUZZER_SPECIFIC_PATCH,
                )
                continue

            # Evaluate patch
            action = context["evaluator"].evaluate(context, diff, detection)
            store_debug_file(context, "action.txt", str(action))
            actions.append(action)
            should_stop = state.update(action, fault_location, rover.final_report)
            if should_stop:
                break

        yield choose_best_action(actions) if len(actions) > 0 else NoPatchAction()


class MartianAgent(AgentProtocol):
    def __init__(
        self,
        fault_localization_llm: LlmApiManager,
        report_parser_llm: LlmApiManager,
        code_generation_llm: LlmApiManager,
        backup_llm: LlmApiManager | None = None,
        max_iterations: int = 1,
    ):
        self._fault_localization_llm = fault_localization_llm
        self._report_parser_llm = report_parser_llm
        self._code_generation_llm = code_generation_llm
        self._backup_llm = backup_llm
        self._max_iterations = max_iterations

    def act(self, context: AgentContext, detection: Detection) -> Iterator[Action]:
        output_directory = (
            context["output_directory"].resolve()
            if "output_directory" in context
            else None
        )
        workflow = Workflow(
            self._fault_localization_llm,
            self._report_parser_llm,
            self._code_generation_llm,
            self._max_iterations,
            output_directory,
            self._backup_llm,
        )
        return workflow.run(context, detection)


def _make_prompt(
    context: AgentContext,
    fault_location: FaultLocation,
    bug_analysis_report: str,
    language: Language,
    imports_insight: str | None = None,
) -> str:
    template = """
Generate a patch on function {function_name} in file {file_path} to fix the vulnerability.
Refer to the report to understand the bug.

## Report

{bug_analysis_report}

## Rules
- Do not change the function signature.
- Do not assume macros or functions that you did not see in the code.
- Do not use fuzzer-specific macros/flags in the patch.
- Do not remove assert or abort statements in the code guarded by fuzzer-specific build flag like `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`.
- If you want to generate a patch that only deletes a code block, be careful not to delete the functionality of the code block.
Removing backdoor code is good but removing the legitimate API calls is not encouraged.
{java_specific_rules}

{imports_section}
"""

    return template.format(
        function_name=fault_location.function_name,
        file_path=fault_location.file.relative_to(context["pool"].source_directory),
        bug_analysis_report=bug_analysis_report,
        imports_section=(
            f"""
## Imports
These imports are available in the file.

```
{imports_insight}
```
"""
            if imports_insight
            else ""
        ).strip(),
        java_specific_rules=(
            """
- If you want to add a new Exception catch, use more specific exception classes. For example, use `ArrayIndexOutOfBoundsException` instead of `RuntimeException`.
"""
            if language == "jvm"
            else ""
        ).strip(),
    ).strip()


def _set_agent_output_directory(
    context: AgentContext, output_directory: Path | None, iteration: int
):
    if output_directory is not None:
        context["output_directory"] = output_directory / f"iter_{iteration}"
        context["output_directory"].mkdir(parents=True, exist_ok=True)


def _is_harness_file(file_path: Path, source_directory: Path) -> bool:
    relative_path = file_path.relative_to(source_directory)
    return (
        "LLVMFuzzerTestOneInput" in file_path.read_text(errors="replace")
        or "fuzz" in str(relative_path)
        or "harness" in str(relative_path)
    )


def _is_fuzzer_specific_patch(diff: str) -> bool:
    for patched_file in PatchSet.from_string(diff):
        for hunk in patched_file:
            for line in hunk:
                if line.is_added:
                    if re.search(r"#if .*FUZZ.*", line.value):
                        return True
    return False
