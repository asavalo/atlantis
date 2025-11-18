import inspect
from typing import Iterator

from python_llm.api.actors import LlmApiManager
from python_aixcc_challenge.detection.models import AIxCCChallengeDeltaMode

from crete.atoms.action import Action, NoPatchAction
from crete.atoms.detection import Detection
from crete.commons.crash_analysis.functions import get_bug_class
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.protocols import AgentProtocol
from crete.framework.analyzer.services.commit.functions import analyze_commit_by_llm
from crete.framework.analyzer.services.jvm_timeout_stacktrace.functions import (
    get_jvm_timeout_stacktrace,
)
from crete.framework.analyzer.services.jvm_stackoverflow_stacktrace.functions import (
    get_jvm_stackoverflow_stacktrace,
)
from crete.framework.code_inspector.functions import get_code_block_from_file
from crete.framework.coder.services.aider import AiderCoder
from crete.framework.fault_localizer.functions import fault_locations_to_files
from crete.framework.fault_localizer.models import FaultLocation
from crete.framework.fault_localizer.protocols import FaultLocalizerProtocol
from crete.framework.fault_localizer.services.sarif import SarifFaultLocalizer
from crete.framework.insighter.services.crash_log import CrashLogInsighter
from crete.framework.insighter.services.crash_log_extractor import CrashLogSummarizer
from crete.framework.insighter.services.stacktrace import StacktraceInsighter

AIDER_USER_PROMPT_TEMPLATE = """
{instruction}

{insights}
""".lstrip()

DEFAULT_INSTRUCTION_TEMPLATE = """Fix {bug_class} vulnerability.

Rules:
- Do not modify outside of the target project.
- Do not modify the fuzz harnesses.
- Do not use fuzzer-specific macros/flags in the patch.
- Do not remove assert or abort statements in the code guarded by fuzzer-specific build flag like `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`.
- If you want to generate a patch that only deletes a code block, be careful not to delete the functionality of the code block.
Removing backdoor code is good but removing the legitimate API calls is not encouraged.
"""

FAULT_LOCATION_GUIDED_INSTRUCTION_TEMPLATE = """
Fix {bug_class} vulnerability from below locations:
{fault_location_code_blocks}
Please focus on above locations to fix the bug.

Rules:
- Do not modify outside of the target project.
- Do not modify the fuzz harnesses.
- Do not use fuzzer-specific macros/flags in the patch.
- Do not remove assert or abort statements in the code guarded by fuzzer-specific build flag like `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`.
- If you want to generate a patch that only deletes a code block, be careful not to delete the functionality of the code block.
Removing backdoor code is good but removing the legitimate API calls is not encouraged.
{jvm_specific_rules}
""".lstrip()

SARIF_ONLY_LOCATION_GUIDED_INSTRUCTION_TEMPLATE = """Fix the vulnerability from the given location.

Bug Type:
{bug_class}

{sarif_report}

Vulnerable Source:
{fault_location_code_blocks}
""".lstrip()


CRASH_LOG_INSIGHTS_TEMPLATE = """
Below is the crash log information:

{crash_log}

""".lstrip()

CRASH_BACKTRACE_INSIGHTS_TEMPLATE = """
Below is the crash backtrace:

{crash_backtrace}

""".lstrip()

COMMIT_ANALYSIS_INSIGHTS_TEMPLATE = """
The vulnerability is caused by a recent change.
Below is the analysis of possible vulnerabilities in the change.
Please fix the vulnerability by following the recommendations.

{commit_analysis}

""".lstrip()

SINGLE_COMMIT_ANALYSIS_TEMPLATE = """
Analysis:
- Vulnerability type: {vulnerability_type}
- Severity: {severity}
- Description: {description}
- Recommendation: {recommendation}
- Problematic lines: \n{problematic_lines}
- Patches to avoid: \n{patches_to_avoid}

""".lstrip()


def _make_crash_log_prompt(
    context: AgentContext,
    detection: Detection,
    fault_locations: list[FaultLocation],
    llm_api_manager: LlmApiManager,
):
    assert len(detection.blobs) > 0, "No blobs found"

    bug_class = get_bug_class(context, detection) or "a"
    relative_fault_locations = _strip_fault_locations(context, fault_locations)
    instruction = (
        DEFAULT_INSTRUCTION_TEMPLATE.format(bug_class=bug_class)
        if len(fault_locations) == 0
        else FAULT_LOCATION_GUIDED_INSTRUCTION_TEMPLATE.format(
            bug_class=bug_class,
            fault_location_code_blocks=_get_fault_location_code_blocks(
                context, relative_fault_locations
            ),
            jvm_specific_rules=inspect.cleandoc(
                """
                - When adding a new Exception catch, use a more specific exception classes. For example, use `ArrayIndexOutOfBoundsException` instead of `RuntimeException`.
                """
            )
            if detection.language == "jvm"
            else "",
        )
    )

    insights = ""

    try:
        insights += _make_commit_analysis_insights(context, detection, llm_api_manager)
    except Exception as e:
        context["logger"].error(f"Error creating commit analysis: {e}")

    try:
        insights += _make_crash_log_insights(context, detection, llm_api_manager)
    except Exception as e:
        context["logger"].error(f"Error creating crash log: {e}")

    try:
        insights += _make_crash_backtrace_insights(context, detection)
    except Exception as e:
        context["logger"].error(f"Error creating crash backtrace: {e}")

    if detection.sarif_report:
        try:
            insights += _make_sarif_report(context, detection)
        except Exception as e:
            context["logger"].error(f"Error creating sarif report: {e}")

    prompt = AIDER_USER_PROMPT_TEMPLATE.format(
        instruction=instruction, insights=insights
    )
    context["logger"].info(f"Aider user prompt: {prompt}")
    return prompt


def _make_sarif_only_location_guided_prompt(
    context: AgentContext,
    detection: Detection,
    fault_locations: list[FaultLocation],
):
    assert detection.sarif_report is not None, "Sarif report is None"

    bug_class = get_bug_class(context, detection) or "a"
    relative_fault_locations = _strip_fault_locations(context, fault_locations)

    return SARIF_ONLY_LOCATION_GUIDED_INSTRUCTION_TEMPLATE.format(
        bug_class=bug_class,
        sarif_report=_make_sarif_report(context, detection),
        fault_location_code_blocks=_get_fault_location_code_blocks(
            context, relative_fault_locations
        ),
    )


def _make_commit_analysis_insights(
    context: AgentContext,
    detection: Detection,
    llm_api_manager: LlmApiManager,
) -> str:
    insights = ""
    if isinstance(detection.mode, AIxCCChallengeDeltaMode):
        commit_analysis = analyze_commit_by_llm(
            context,
            detection,
            llm_api_manager,
        )
        if commit_analysis is not None and len(commit_analysis) > 0:
            insights = COMMIT_ANALYSIS_INSIGHTS_TEMPLATE.format(
                commit_analysis="\n".join(
                    SINGLE_COMMIT_ANALYSIS_TEMPLATE.format(
                        vulnerability_type=analysis.vulnerability_type,
                        severity=analysis.severity,
                        description=analysis.description,
                        recommendation=analysis.recommendation,
                        problematic_lines=analysis.problematic_lines,
                        patches_to_avoid=analysis.patches_to_avoid,
                    )
                    for analysis in commit_analysis
                ),
            )
            context["logger"].info(f"Commit analysis: \n{insights}")
    return insights


def _make_crash_log_insights(
    context: AgentContext,
    detection: Detection,
    llm_api_manager: LlmApiManager,
) -> str:
    insights = ""
    crash_log = CrashLogInsighter().create(context, detection)

    if crash_log and detection.language == "jvm":
        crash_log = _check_jvm_crash_type(context, detection, crash_log)

    if crash_log:
        try:
            crash_log = CrashLogSummarizer(llm_api_manager, crash_log).create(
                context, detection
            )
        except Exception as e:
            context["logger"].error(f"Error creating summary of crash log: {e}")

    if crash_log:
        insights += CRASH_LOG_INSIGHTS_TEMPLATE.format(
            crash_log=crash_log,
        )

    return insights


def _check_jvm_crash_type(
    context: AgentContext, detection: Detection, original_crash_log: str
) -> str:
    if "ERROR: libFuzzer: timeout" in original_crash_log:
        crash_log = get_jvm_timeout_stacktrace(context, detection)
    elif "FuzzerSecurityIssueLow: Stack overflow" in original_crash_log:
        crash_log = get_jvm_stackoverflow_stacktrace(context, detection)
    else:
        crash_log = original_crash_log

    if crash_log is None:
        return original_crash_log
    else:
        return crash_log


def _make_crash_backtrace_insights(
    context: AgentContext,
    detection: Detection,
) -> str:
    insights = ""

    crash_backtrace = StacktraceInsighter().create(context, detection)
    if crash_backtrace:
        insights += CRASH_BACKTRACE_INSIGHTS_TEMPLATE.format(
            crash_backtrace=crash_backtrace,
        )

    return insights


def _make_sarif_report(context: AgentContext, detection: Detection) -> str:
    assert detection.sarif_report is not None, "Sarif report is None"
    sarif_result = SarifFaultLocalizer().localize(context, detection)

    sarif_report_str = "Static Analysis Report:\n"
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


def _get_fault_location_code_blocks(
    context: AgentContext, fault_locations: list[FaultLocation]
) -> str:
    prompt = ""
    for fault_location in fault_locations:
        prompt += "file: " + str(fault_location.file)
        if fault_location.function_name is not None:
            prompt += " function: " + fault_location.function_name
        if fault_location.line_range is not None:
            prompt += (
                f" line: {fault_location.line_range[0]}:{fault_location.line_range[1]}"
            )
            prompt += f"\ncode:\n```\n{
                get_code_block_from_file(
                    context,
                    fault_location.file,
                    fault_location.line_range[0],
                    fault_location.line_range[1],
                )
            }\n```\n"
        else:
            prompt += "\n"
    return prompt


def _strip_fault_locations(
    context: AgentContext, fault_locations: list[FaultLocation]
) -> list[FaultLocation]:
    result: list[FaultLocation] = []
    for fault_location in fault_locations:
        if fault_location.file.is_relative_to(context["pool"].source_directory):
            result.append(
                FaultLocation(
                    file=fault_location.file.relative_to(
                        context["pool"].source_directory
                    ),
                    function_name=fault_location.function_name,
                    line_range=fault_location.line_range,
                )
            )
    return result


def _get_fault_locations(fault_locations: list[FaultLocation]) -> str:  # pyright: ignore[reportUnusedFunction]
    prompt = ""
    for fault_location in fault_locations:
        prompt += "file: " + str(fault_location.file)
        if fault_location.function_name is not None:
            prompt += " function: " + fault_location.function_name
        if fault_location.line_range is not None:
            prompt += (
                " line: "
                + str(fault_location.line_range[0])
                + ":"
                + str(fault_location.line_range[1])
            )
        prompt += "\n"
    prompt += "\n"

    return prompt


class AiderAgent(AgentProtocol):
    def __init__(
        self,
        fault_localizer: FaultLocalizerProtocol,
        llm_api_manager: LlmApiManager,
        max_reflections: int = 3,
        use_compile_feedback: bool = False,
    ) -> None:
        self._fault_localizer = fault_localizer
        self._max_reflections = max_reflections
        self._use_compile_feedback = use_compile_feedback
        self._llm_api_manager = llm_api_manager

    def act(self, context: AgentContext, detection: Detection) -> Iterator[Action]:
        fault_localization_result = self._fault_localizer.localize(context, detection)

        if len(fault_localization_result.locations) == 0 and detection.sarif_report:
            fault_localization_result = SarifFaultLocalizer().localize(
                context, detection
            )

        target_files = fault_locations_to_files(fault_localization_result.locations)

        coder = AiderCoder(
            context,
            detection,
            self._llm_api_manager,
            target_files,
            self._max_reflections,
            self._use_compile_feedback,
        )
        if detection.blobs:
            prompt = _make_crash_log_prompt(
                context,
                detection,
                fault_localization_result.locations,
                self._llm_api_manager,
            )
        elif detection.sarif_report:
            prompt = _make_sarif_only_location_guided_prompt(
                context, detection, fault_localization_result.locations
            )
        else:
            raise ValueError("No valid detection (no blobs or sarif report found)")

        diff = coder.run(context, prompt)
        context["logger"].info(f"Suggested diff: {diff}")
        if diff is None or len(diff.strip()) == 0:
            yield NoPatchAction()
        else:
            yield context["evaluator"].evaluate(context, diff, detection)
