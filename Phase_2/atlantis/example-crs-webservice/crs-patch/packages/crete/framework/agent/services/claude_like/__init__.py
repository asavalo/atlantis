from pathlib import Path
from typing import Iterator

from python_llm.api.actors import LlmApiManager

from crete.atoms.action import (
    Action,
    CompilableDiffAction,
    NoPatchAction,
    UncompilableDiffAction,
    VulnerableDiffAction,
    WrongDiffAction,
    choose_best_action,
)
from crete.atoms.detection import Detection
from crete.commons.crash_analysis.functions import get_bug_class
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.functions import store_debug_file
from crete.framework.agent.protocols import AgentProtocol
from crete.framework.agent.services.claude_like.prompts import (
    CLAUDE_CODE_USER_PROMPT_TEMPLATE,
    CLAUDE_CODE_USER_PROMPT_TEMPLATE_WITH_FEEDBACK,
    DEFAULT_INSIGHTS_TEMPLATE,
    DEFAULT_SARIF_INSIGHT_TEMPLATE,
    FAILED_PATCH_TEMPLATE,
)
from crete.framework.analyzer.services.jvm_stackoverflow_stacktrace.functions import (
    get_jvm_stackoverflow_stacktrace,
)
from crete.framework.analyzer.services.jvm_timeout_stacktrace.functions import (
    get_jvm_timeout_stacktrace,
)
from crete.framework.coder.services.claude_like import ClaudeLikeCoder
from crete.framework.fault_localizer.services.sarif import SarifFaultLocalizer
from crete.framework.insighter.protocols import InsighterProtocol
from crete.framework.insighter.services.crash_log import CrashLogInsighter


class ClaudeLikeAgent(AgentProtocol):
    def __init__(
        self,
        insighters: list[InsighterProtocol] = [],
        max_iterations: int = 3,
    ) -> None:
        self._insighters = insighters
        self._max_iterations = max_iterations

    def act(self, context: AgentContext, detection: Detection) -> Iterator[Action]:
        output_directory = (
            context["output_directory"] if "output_directory" in context else None
        )

        failed_patches = ""

        actions: list[Action] = []

        for context in _iterate_with_output_directory(
            context, output_directory, self._max_iterations
        ):
            coder = ClaudeLikeCoder(
                agent_context=context,
                detection=detection,
                llm_api_manager=LlmApiManager.from_environment(
                    model="claude-3-7-sonnet-20250219", custom_llm_provider="anthropic"
                ),
            )
            prompt = make_prompt(context, detection, failed_patches)
            diff = coder.run(context, prompt)

            action: Action
            if diff is None or len(diff.strip()) == 0:
                action = NoPatchAction()
            else:
                action = context["evaluator"].evaluate(context, diff, detection)

            store_debug_file(context, "prompt.txt", prompt)
            store_debug_file(
                context,
                "diff.txt",
                diff.decode(errors="replace") if diff is not None else "",
            )

            actions.append(action)

            if isinstance(
                action,
                (
                    VulnerableDiffAction,
                    CompilableDiffAction,
                    UncompilableDiffAction,
                    WrongDiffAction,
                ),
            ):
                failed_patches += FAILED_PATCH_TEMPLATE.format(
                    failed_patch=diff.decode(errors="replace")
                    if diff is not None
                    else ""
                )
            else:
                break

        yield choose_best_action(actions)


def _get_crash_log(
    context: AgentContext, detection: Detection, original_log: str
) -> str:
    match detection.language:
        case "c" | "c++" | "cpp":
            return original_log
        case "jvm":
            if "ERROR: libFuzzer: timeout" in original_log:
                crash_log = get_jvm_timeout_stacktrace(context, detection)
            elif "FuzzerSecurityIssueLow: Stack overflow" in original_log:
                crash_log = get_jvm_stackoverflow_stacktrace(context, detection)
            else:
                crash_log = original_log

            if crash_log is None:
                return original_log

            return crash_log


def make_prompt(
    context: AgentContext, detection: Detection, failed_patches: str
) -> str:
    bug_class = get_bug_class(context, detection) or ""

    insight_list: list[str] = []

    if detection.sarif_report is not None:
        insight = DEFAULT_SARIF_INSIGHT_TEMPLATE.format(
            sarif_report=_make_sarif_report(context, detection)
        )

        insight_list.append(insight)

    if len(detection.blobs) != 0:
        crash_log = CrashLogInsighter().create(context, detection)
        if crash_log is None:
            context["logger"].warning("Failed to generate crash log")
            insight = ""
        else:
            crash_log = _get_crash_log(context, detection, crash_log)

            insight = DEFAULT_INSIGHTS_TEMPLATE.format(crash_log=crash_log)

        insight_list.append(insight)

    if len(insight_list) == 0:
        assert False, "No insights provided for the prompt"

    insights = "\n\n".join(insight_list)

    if failed_patches == "":
        return CLAUDE_CODE_USER_PROMPT_TEMPLATE.format(
            bug_class=bug_class, insights=insights
        )
    else:
        return CLAUDE_CODE_USER_PROMPT_TEMPLATE_WITH_FEEDBACK.format(
            bug_class=bug_class, insights=insights, failed_patch=failed_patches
        )


def _make_sarif_report(context: AgentContext, detection: Detection) -> str:
    assert detection.sarif_report is not None, "Sarif report is None"
    sarif_result = SarifFaultLocalizer().localize(context, detection)

    sarif_report_str = ""
    if sarif_result.description:
        sarif_report_str += f"* Description:\n{sarif_result.description}\n"

    for i, fault_location in enumerate(sarif_result.locations):
        sarif_report_str += f"* Bug location {i + 1}:\n"
        sarif_report_str += f" - File: {fault_location.file}\n"
        if fault_location.line_range:
            sarif_report_str += f" - Line range: {fault_location.line_range}\n"
        if fault_location.function_name:
            sarif_report_str += f" - Function name: {fault_location.function_name}\n"

    return sarif_report_str


def _iterate_with_output_directory(
    context: AgentContext, output_directory: Path | None, max_iterations: int
) -> Iterator[AgentContext]:
    original_output_directory = context.get("output_directory", None)
    try:
        for i in range(max_iterations):
            if output_directory is not None:
                context["output_directory"] = output_directory / f"iter_{i}"
                context["output_directory"].mkdir(parents=True, exist_ok=True)
            yield context
    finally:
        if original_output_directory is not None:
            context["output_directory"] = original_output_directory
        else:
            context.pop("output_directory", None)
