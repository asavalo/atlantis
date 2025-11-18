import inspect
import string
from typing import Iterator

from python_aixcc_challenge.language.types import Language
from python_aixcc_challenge.detection.models import AIxCCChallengeDeltaMode
from python_llm.api.actors import LlmApiManager

from crete.atoms.action import Action, NoPatchAction, UncompilableDiffAction
from crete.atoms.detection import Detection
from crete.commons.crash_analysis.functions import get_bug_class
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.protocols import AgentProtocol
from crete.framework.analyzer.services.jvm_timeout_stacktrace.functions import (
    get_jvm_timeout_stacktrace,
)
from crete.framework.analyzer.services.jvm_stackoverflow_stacktrace.functions import (
    get_jvm_stackoverflow_stacktrace,
)
from crete.framework.analyzer.services.commit.functions import analyze_commit_by_llm
from crete.framework.code_inspector.functions import get_code_block_from_file
from crete.framework.coder.protocols import CoderProtocol
from crete.framework.coder.services.swe import SweCoder
from crete.framework.fault_localizer.models import FaultLocation
from crete.framework.fault_localizer.protocols import FaultLocalizerProtocol
from crete.framework.fault_localizer.services.sarif import SarifFaultLocalizer
from crete.framework.insighter.services.crash_log import CrashLogInsighter
from crete.framework.insighter.services.stacktrace import StacktraceInsighter

PATCH_RULES = inspect.cleandoc(
    """
    Rules:
    - Do not modify outside of the target project.
    - Do not modify the fuzz harnesses.
    - Do not use fuzzer-specific macros/flags in the patch.
    - Do not remove assert or abort statements in the code guarded by fuzzer-specific build flag like `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`.
    - If you want to generate a patch that only deletes a code block, be careful not to delete the functionality of the code block.
    Removing backdoor code is good but removing the legitimate API calls is not encouraged.
    {jvm_specific_rules}
    """
)

JVM_PATCH_RULES = inspect.cleandoc(
    """
    - When adding a new Exception catch, use a more specific exception classes. For example, use `ArrayIndexOutOfBoundsException` instead of `RuntimeException`.
    """
)

DEFAULT_INSTRUCTION_TEMPLATE = """Fix {bug_class} vulnerability.

{patch_rules}
"""

FAULT_LOCATION_GUIDED_INSTRUCTION_TEMPLATE = """Fix {bug_class} vulnerability from below locations.
{sarif_report}
{fault_location_code_blocks}

{patch_rules}
""".lstrip()

SARIF_ONLY_LOCATION_GUIDED_INSTRUCTION_TEMPLATE = """
Below is the location of the vulnerable source within this codebase and the bug type associated with the vulnerability:

Vulnerable Source:
{fault_location_code_blocks}

Bug Type:
{bug_class}

Fix the vulnerability from the given location
Even if you determine that this code is not vulnerable, please modify the code to make it more secure.
You must modify the code only within the code block I have provided.
You should address vulnerabilities with **MINIMAL** changes.
{jvm_specific_rules}
""".lstrip()

DEFAULT_INSIGHTS_TEMPLATE = """
Below is the crash log:

{crash_log}

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


class SweAgent(AgentProtocol):
    def __init__(
        self,
        fault_localizer: FaultLocalizerProtocol,
        llm_api_manager: LlmApiManager,
        max_feedback: int = 0,
    ):
        self._fault_localizer = fault_localizer
        self._max_feedback = max_feedback
        self._llm_api_manager = llm_api_manager

    def act(self, context: AgentContext, detection: Detection) -> Iterator[Action]:
        environment = context["pool"].restore(context)

        # restoring environment is necessary to clean all build artifacts for SWE-agent
        environment.restore(context)

        fault_locations = self._fault_localizer.localize(context, detection).locations
        relative_fault_locations = self._strip_fault_locations(context, fault_locations)

        coder = SweCoder(context, detection, self._llm_api_manager)
        prompt = self._make_base_prompt(context, detection, relative_fault_locations)

        action = self._run_coder(context, detection, coder, prompt)
        for _ in range(self._max_feedback):
            match action:
                case UncompilableDiffAction(diff=diff, stdout=stdout, stderr=stderr):
                    prompt = f"- Your previous code is not compilable. Please give another patch. - Diff: ```diff\n{diff}```\n- Stdout: {stdout.decode()}\n- Stderr: {stderr.decode()}"
                    action = self._run_coder(context, detection, coder, prompt)
                case _:
                    break

        yield action

    def _run_coder(
        self,
        context: AgentContext,
        detection: Detection,
        coder: CoderProtocol,
        prompt: str,
    ) -> Action:
        diff = coder.run(context, prompt)

        if diff is None or len(diff.strip()) == 0:
            return NoPatchAction()

        return context["evaluator"].evaluate(context, diff, detection)

    def _strip_fault_locations(
        self, context: AgentContext, fault_locations: list[FaultLocation]
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

    def _remove_unprintable_chracters(self, text: str) -> str:
        return "".join(character for character in text if character in string.printable)

    def _make_base_prompt(
        self,
        context: AgentContext,
        detection: Detection,
        fault_locations: list[FaultLocation],
    ) -> str:
        bug_class = get_bug_class(context, detection) or "a"

        prompt = ""

        # Sarif-only patch.
        if (len(detection.blobs) == 0) and (detection.sarif_report is not None):
            instruction = _make_sarif_only_location_guided_instruction(
                bug_class,
                self._get_fault_location_code_blocks(context, fault_locations),
                detection.language,
            )
        # Fault location guided patch.
        elif fault_locations:
            instruction = _make_fault_location_guided_instruction(
                bug_class,
                self._get_fault_location_code_blocks(context, fault_locations),
                _get_sarif_report(context, detection),
                detection.language,
            )
        # Default patch.
        else:
            instruction = _make_default_instruction(bug_class, detection.language)

        prompt += instruction
        prompt += self._make_commit_analysis_insights(context, detection)
        try:
            prompt += self._get_crash_insight(context, detection)
        except Exception as e:
            context["logger"].error(f"Error creating commit analysis: {e}")
        return prompt

    def _get_fault_location_code_blocks(
        self, context: AgentContext, fault_locations: list[FaultLocation]
    ) -> str:
        prompt = ""
        for fault_location in fault_locations:
            prompt += "file: " + str(fault_location.file)
            if fault_location.function_name is not None:
                prompt += " function: " + fault_location.function_name
            if fault_location.line_range is not None:
                prompt += f" line: {fault_location.line_range[0]}:{fault_location.line_range[1]}"
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

    def _get_fault_locations(self, fault_locations: list[FaultLocation]) -> str:
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

    def _make_commit_analysis_insights(
        self,
        context: AgentContext,
        detection: Detection,
    ) -> str:
        insights = ""
        if isinstance(detection.mode, AIxCCChallengeDeltaMode):
            commit_analysis = analyze_commit_by_llm(
                context,
                detection,
                self._llm_api_manager,
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

    def _get_crash_insight(self, context: AgentContext, detection: Detection) -> str:
        prompt = ""

        crash_log_insight = CrashLogInsighter().create(context, detection)
        if crash_log_insight is not None and detection.language == "jvm":
            crash_log_insight = _check_jvm_crash_type(
                context, detection, crash_log_insight
            )
        if crash_log_insight is not None:
            prompt += f"Below is the crash log that triggered the vulnerability\n{crash_log_insight}\n\n"

        stacktrace_insight = StacktraceInsighter().create(context, detection)
        if stacktrace_insight is not None:
            prompt += f"Below is the stack trace that triggered the vulnerability\n{stacktrace_insight}\n\n"

        return self._remove_unprintable_chracters(prompt)


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


def _get_sarif_report(context: AgentContext, detection: Detection) -> str:
    if detection.sarif_report is None:
        return ""

    sarif_fault_localizer = SarifFaultLocalizer()
    fault_localization_result = sarif_fault_localizer.localize(context, detection)
    sarif_report = ""
    if fault_localization_result.description:
        sarif_report += (
            f"Vulnerability Description: {fault_localization_result.description}\n"
        )

    for i, fault_location in enumerate(fault_localization_result.locations):
        sarif_report += f"Vulnerable Source #{i}:\n"
        sarif_report += f"- File: {fault_location.file}\n"
        if fault_location.function_name:
            sarif_report += f"- Function: {fault_location.function_name}\n"
        if fault_location.line_range:
            sarif_report += f"- Line: {fault_location.line_range[0]}:{fault_location.line_range[1]}\n"

    return sarif_report


def _make_default_instruction(
    bug_class: str,
    language: Language,
) -> str:
    return DEFAULT_INSTRUCTION_TEMPLATE.format(
        bug_class=bug_class,
        patch_rules=PATCH_RULES.format(
            jvm_specific_rules=JVM_PATCH_RULES if language == "jvm" else "",
        ),
    )


def _make_fault_location_guided_instruction(
    bug_class: str,
    fault_location_code_blocks: str,
    sarif_report: str,
    language: Language,
) -> str:
    return FAULT_LOCATION_GUIDED_INSTRUCTION_TEMPLATE.format(
        bug_class=bug_class,
        sarif_report=sarif_report,
        fault_location_code_blocks=fault_location_code_blocks,
        patch_rules=PATCH_RULES.format(
            jvm_specific_rules=JVM_PATCH_RULES if language == "jvm" else "",
        ),
    )


def _make_sarif_only_location_guided_instruction(
    bug_class: str,
    fault_location_code_blocks: str,
    language: Language,
) -> str:
    return SARIF_ONLY_LOCATION_GUIDED_INSTRUCTION_TEMPLATE.format(
        bug_class=bug_class,
        fault_location_code_blocks=fault_location_code_blocks,
        jvm_specific_rules=JVM_PATCH_RULES if language == "jvm" else "",
    )
