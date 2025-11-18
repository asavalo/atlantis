import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, cast

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field
from python_file_system.directory.context_managers import changed_directory
from python_llm.agents.react import run_react_agent
from python_llm.api.actors import LlmApiManager
from unidiff import PatchSet

from crete.atoms.action import (
    Action,
    CompilableDiffAction,
    NoPatchAction,
    VulnerableDiffAction,
)
from crete.atoms.detection import Detection
from crete.commons.crash_analysis.functions import extract_bug_class, get_crash_stacks
from crete.framework.agent.functions import store_debug_file
from crete.framework.analyzer.services.commit.functions import get_ref_diff
from crete.framework.analyzer.services.jvm_stackoverflow_stacktrace import (
    JVMStackOverflowStacktraceAnalyzer,
)
from crete.framework.analyzer.services.jvm_timeout_stacktrace import (
    JVMTimeoutStacktraceAnalyzer,
)
from crete.framework.code_inspector.functions import search_symbol_in_codebase
from crete.framework.environment.functions import resolve_project_path
from crete.framework.fault_localizer.contexts import FaultLocalizationContext
from crete.framework.fault_localizer.models import (
    FaultLocalizationResult,
    FaultLocation,
)
from crete.framework.fault_localizer.protocols import FaultLocalizerProtocol
from crete.framework.fault_localizer.services.sarif import SarifFaultLocalizer
from crete.framework.insighter.services.crash_log import CrashLogInsighter
from crete.framework.tools.services import (
    SearchStringTool,
    SearchSymbolTool,
    ViewFileTool,
)


class NoPatchReason(Enum):
    HARNESS_FILE_LOCALIZED = "harness_file_localized"
    FUZZER_SPECIFIC_PATCH = "fuzzer_specific_patch"
    OTHER = "other"


@dataclass
class FeedbackRecord:
    action: VulnerableDiffAction | CompilableDiffAction | NoPatchAction
    fault_location: FaultLocation
    report: str
    no_patch_reason: NoPatchReason | None = None


class BuggyFunction(BaseModel):
    file_path: str = Field(description="Path to the file where the bug is located")
    function_name: str = Field(
        description="Name of the function where the bug is located"
    )


class CodeRoverKFaultLocalizer(FaultLocalizerProtocol):
    """
    From given crash report, it explores the source code with code inspection (e.g., goto definition)
    to find the fault location.
    """

    def __init__(
        self,
        analysis_llm: LlmApiManager,
        parsing_llm: LlmApiManager,
    ) -> None:
        self._analysis_llm = analysis_llm
        self._parsing_llm = parsing_llm
        self._final_report: str | None = None

    @property
    def final_report(self) -> str:
        assert self._final_report is not None, "Rover did not run yet"
        return self._final_report

    def localize(
        self,
        context: FaultLocalizationContext,
        detection: Detection,
        previous_record: FeedbackRecord | None = None,
    ) -> FaultLocalizationResult:
        self._final_report = self._generate_report(context, detection, previous_record)
        if self._final_report is None:
            return FaultLocalizationResult(locations=[])

        store_debug_file(context, "coderover_k_report.txt", self._final_report)

        # Since we cannot set structured output to the ReACT agent, we'll have
        # additional step for parsing the output using 1) regex and 2) LLM
        fault_location = self._parse_fault_location(
            context, detection, self._final_report
        )
        context["logger"].info(f"Found fault location: {fault_location}")
        return FaultLocalizationResult(
            locations=[fault_location] if fault_location else []
        )

    def _generate_report(
        self,
        context: FaultLocalizationContext,
        detection: Detection,
        previous_record: FeedbackRecord | None = None,
    ) -> str | None:
        messages = [
            SystemMessage(
                """Your task is to analyze the bug and provide a patch plan to fix the bug in the codebase.
I will give you the crash log and additional information to help you analyze the bug.

Note that the location of the bug is DIFFERENT from the crash location.
The crash location is where the program crashes, but the bug location is where the bug is introduced.

You'll have to get enough code context to understand the bug.
Fully utilize the given code inspection tools to find the bug location.
"""
            ),
            HumanMessage(
                """
Generate a bug analysis report.
The report should contain the bug location and the patch plan to fix the bug.
- What is the root cause of the bug?
- What part of the codebase could be responsible for the bug?
- What is the correct patch to fix the bug?
- What is the side effect of the patch?

## FORMAT

For each bug location, you should provide the file path, function name in below format:
**File Path**: `path/to/file.c`
**Function Name**: `function_name`

## Rules

- Fully utilize the given code inspection tools to get the code context.
- Don't assume any functions or macros that you did not see in the code. Call the tools to make sure.
- Don't ask to get confirmation. Proceed with your best guess.
- Don't pinpoint bug location in the fuzz harness or test cases.

{guidance_section}

{crash_log_section}

{sarif_report_section}

{delta_mode_ref_diff_section}
""".format(
                    guidance_section=_make_guidance_section(detection),
                    crash_log_section=_make_crash_log_section(context, detection),
                    sarif_report_section=_make_sarif_report_section(context, detection),
                    delta_mode_ref_diff_section=_make_delta_mode_ref_diff_section(
                        context, detection
                    ),
                ).strip()
            ),
        ]

        if previous_record:
            messages.append(AIMessage(previous_record.report))  # type: ignore
            messages.append(
                HumanMessage(
                    _make_feedback_prompt(
                        previous_record.action,
                        bug_class_changed=_has_bug_class_changed(
                            CrashLogInsighter().create(context, detection),
                            _get_crash_log_from_action(previous_record.action),
                        ),
                        no_patch_reason=previous_record.no_patch_reason,
                    )
                )
            )

        store_debug_file(
            context,
            "coderover_k_inputs.json",
            json.dumps([msg.model_dump() for msg in messages], indent=2),
        )

        tools = self._get_tools(context, detection)

        with changed_directory(context["pool"].source_directory):
            return run_react_agent(self._analysis_llm, tools, messages)

    def _get_tools(
        self,
        context: FaultLocalizationContext,
        detection: Detection,
    ) -> list[BaseTool]:
        tools: list[BaseTool] = [
            SearchSymbolTool(
                context, context["pool"].source_directory, with_line_number=True
            ),
            SearchStringTool(context, context["pool"].source_directory),
            ViewFileTool(context, with_line_number=True),
        ]
        return tools

    def _parse_fault_location(
        self, context: FaultLocalizationContext, detection: Detection, report: str
    ) -> FaultLocation | None:
        fault_location = self._parse_raw_fault_location(context, report)
        if fault_location is None:
            return None

        assert fault_location.function_name is not None
        assert fault_location.file is not None

        # LLM sometimes returns correct fault location but in wrong format.
        # We'll adjust the function name and file path to make it correct.
        function_name = _calibrate_function_name(fault_location.function_name)
        file_path = _calibrate_file_path(
            fault_location.file, context, detection, function_name
        )

        if file_path is None:
            return None

        return FaultLocation(file_path, function_name, None)

    def _parse_raw_fault_location(
        self,
        context: FaultLocalizationContext,
        report: str,
    ) -> FaultLocation | None:
        fault_location = self._parse_report_using_regex(report)
        if fault_location:
            context["logger"].debug("Successfully parsed the report using regex")
            return fault_location

        context["logger"].debug("Failed to parse the report using regex... Trying LLM")
        return self._parse_report_using_llm(report)

    def _parse_report_using_regex(self, report: str) -> FaultLocation | None:
        file_path_str = _extract_match(
            report, r"\*?\*?File Path\*?\*?:\s*`?([^`\s]+)`?"
        )
        function_name = _extract_match(
            report, r"\*?\*?Function Name\*?\*?:\s*`?([^`\s]+)`?"
        )

        if not file_path_str or not function_name:
            return None

        return FaultLocation(Path(file_path_str), function_name, None)

    def _parse_report_using_llm(self, report: str) -> FaultLocation | None:
        chat_model = self._parsing_llm.langchain_litellm()
        buggy_function = cast(
            Optional[BuggyFunction],
            chat_model.with_structured_output(BuggyFunction).invoke(  # type: ignore
                f"Extract the buggy function from the report:\n\n{report}"
            ),
        )

        if buggy_function is None:
            return None

        file_path_str = buggy_function.file_path
        function_name = buggy_function.function_name
        return FaultLocation(Path(file_path_str), function_name, None)


def _extract_match(text: str, pattern: str) -> Optional[str]:
    match = re.search(pattern, text)
    return match.group(1) if match else None


def _calibrate_function_name(function_name: str) -> str:
    # if function name is "foo(...)" then remove (...) part
    match = re.match(r"^(.+?)\((.*)\)", function_name)
    if match:
        return match.group(1)
    return function_name


def _calibrate_file_path(
    file_path: Path,
    context: FaultLocalizationContext,
    detection: Detection,
    function_name: str,
) -> Path | None:
    resolved_path = resolve_project_path(file_path, context["pool"].source_directory)
    if resolved_path:
        return resolved_path

    # While the function name is correct, but the file path could be wrong.
    # We'll try to find the correct file path by searching the function name.
    node = search_symbol_in_codebase(context, function_name)
    if node is None:
        return None

    return node.file


def _make_feedback_prompt(
    action: Action,
    bug_class_changed: bool,
    no_patch_reason: NoPatchReason | None = None,
) -> str:
    feedback_prompt = """{feedback_message}

{previous_patch_diff_section}

Try again and give me another bug analysis report.
"""

    return feedback_prompt.format(
        feedback_message=_make_feedback_message(
            action, bug_class_changed, no_patch_reason
        ),
        previous_patch_diff_section=_make_previous_patch_diff_section(action),
    ).strip()


def _make_feedback_message(
    action: Action,
    bug_class_changed: bool,
    no_patch_reason: NoPatchReason | None = None,
) -> str:
    match action:
        case VulnerableDiffAction() if bug_class_changed:
            crash_log = _get_crash_log_from_action(action)
            assert crash_log is not None
            return f"""It fixed the bug but now it introduces a new bug.

Here's the new crash log:

<crash_log>
{crash_log}
</crash_log>
""".strip()
        case VulnerableDiffAction():
            return "I tried to fix the bug but it didn't fix the bug."
        case CompilableDiffAction():
            return "I tried to fix the bug but it harms the functionality."
        case NoPatchAction():
            assert no_patch_reason is not None
            match no_patch_reason:
                case NoPatchReason.HARNESS_FILE_LOCALIZED:
                    return "You localized a harness file which you should not do."
                case NoPatchReason.FUZZER_SPECIFIC_PATCH:
                    return """You generated a fuzzer-specific patch.
Don't use fuzzer-specific macros/flags in the patch."""
                case NoPatchReason.OTHER:
                    return "I tried to fix the bug but there's no function in the codebase."
        case _:
            assert False, "Unreachable"


def _make_previous_patch_diff_section(action: Action) -> str:
    match action:
        case VulnerableDiffAction() | CompilableDiffAction():
            return f"""This is the previous patch diff that I tried:

<previous_patch_diff>
{action.diff.decode(errors="replace")}
</previous_patch_diff>
""".strip()
        case _:
            return ""


def _get_crash_log_from_action(action: Action) -> str | None:
    match action:
        case VulnerableDiffAction(stdout=stdout):
            return stdout.decode(errors="replace")
        case _:
            return None


def _has_bug_class_changed(
    old_crash_log: str | None, new_crash_log: str | None
) -> bool:
    if old_crash_log is None or new_crash_log is None:
        return False

    old_bug_class = extract_bug_class(old_crash_log)
    new_bug_class = extract_bug_class(new_crash_log)
    return old_bug_class != new_bug_class


def _is_specific_bug_class_with_unhelpful_stacktrace(
    context: FaultLocalizationContext,
    detection: Detection,
    crash_log: str,
    bug_class_patterns: list[str],
) -> bool:
    bug_class = extract_bug_class(crash_log)
    return (
        detection.language == "jvm"
        and bug_class is not None
        and any(
            re.search(pattern, bug_class, re.IGNORECASE) is not None
            for pattern in bug_class_patterns
        )
        and not get_crash_stacks(context, detection)
    )


def _make_crash_log_section(
    context: FaultLocalizationContext, detection: Detection
) -> str:
    crash_log = CrashLogInsighter().create(context, detection)
    if crash_log is None:
        return ""

    if _is_specific_bug_class_with_unhelpful_stacktrace(
        context, detection, crash_log, ["timeout"]
    ) and (jstack_output := JVMTimeoutStacktraceAnalyzer().analyze(context, detection)):
        return f"""## Crash report

The libfuzzer reproducer crashed due to **timeout**.

Since the crash log does not contain the stacktrace, use the JVM threads stacktrace to find the bug location.
Focus on the main thread stacktrace.

<jstack>
{jstack_output.decode(errors="replace")}
</jstack>
""".strip()

    if _is_specific_bug_class_with_unhelpful_stacktrace(
        context, detection, crash_log, ["stackoverflow", "stack overflow"]
    ) and (
        stacktrace := JVMStackOverflowStacktraceAnalyzer().analyze(context, detection)
    ):
        return f"""## Crash report

The libfuzzer reproducer crashed due to **Stack Overflow**.

<stacktrace>
{stacktrace}
</stacktrace>
""".strip()

    return f"""## Crash report

<crash_log>
{crash_log}
</crash_log>
""".strip()


def _make_sarif_report_section(
    context: FaultLocalizationContext, detection: Detection
) -> str:
    if not detection.sarif_report:
        return ""

    sarif_result = SarifFaultLocalizer().localize(context, detection)
    sarif_report_str = "## The SARIF report\n"
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


def _make_delta_mode_ref_diff_section(
    context: FaultLocalizationContext, detection: Detection
) -> str:
    if detection.mode is None or detection.mode.type != "delta":
        return ""

    ref_diff = get_ref_diff(context, detection)
    if ref_diff is None:
        return ""

    if _is_too_large_diff(ref_diff):
        context["logger"].warning("The diff is too large. Skipping the diff section.")
        return ""

    return f"""## Bug Introduced Diff

Before the following diff, the bug was not introduced.
But after the following diff, the bug is introduced.
Refer to the diff to find the bug location.
Note that the bug could exist in the diff or in other code related to the diff.

<ref_diff>
{ref_diff}
</ref_diff>
""".strip()


def _is_too_large_diff(diff: str) -> bool:
    patch_set = PatchSet.from_string(diff)
    hunk_count = len([hunk for patched_file in patch_set for hunk in patched_file])
    return hunk_count > 5


def _make_guidance_section(detection: Detection) -> str:
    if detection.language == "jvm":
        return """
## Guidance

- Consider the possibility that the bug is a backdoor. If it's the case, remove the backdoor code.
- Consider the possibility that the bug is using a unsafe function. If it's the case, find the correct function in the codebase, and use it instead.
"""

    return ""
