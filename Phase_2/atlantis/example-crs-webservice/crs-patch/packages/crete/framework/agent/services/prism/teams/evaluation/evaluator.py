import inspect
import re
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from python_aixcc_challenge.detection.models import AIxCCChallengeDeltaMode
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as SarifReport,
)
from sarif.sarif_model import Result

from crete.atoms.action import (
    Action,
    SoundDiffAction,
    UncompilableDiffAction,
    UnknownErrorAction,
    VulnerableDiffAction,
)
from crete.atoms.detection import Detection
from crete.commons.crash_analysis.functions import get_crash_stacks
from crete.commons.interaction.exceptions import CommandInteractionError, TimeoutExpired
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.prism.states.common_state import PatchStatus
from crete.framework.agent.services.prism.states.evaluation_team_state import (
    EvaluationTeamState,
)
from crete.framework.agent.services.prism.teams.base_agent import BaseAgent
from crete.framework.analyzer.services.commit.functions import (
    get_all_diff,
)
from crete.framework.analyzer.services.jvm_stackoverflow_stacktrace import (
    JVMStackOverflowStacktraceAnalyzer,
)
from crete.framework.analyzer.services.jvm_timeout_stacktrace import (
    JVMTimeoutStacktraceAnalyzer,
)
from crete.framework.environment.exceptions import (
    ChallengePoVFoundError,
    ChallengeTestFailedError,
)


class Evaluator(BaseAgent):
    language_map = {
        "c": "c",
        "c++": "cpp",
        "cpp": "cpp",
        "java": "java",
        "jvm": "java",
    }
    abbreviated_log_template: str = "{log}\n... [TRUNCATED]"
    internal_tests_failure_prompt = inspect.cleandoc(
        """
        Your patch has fixed the issue, but the tests are failing.
        Here are some possible reasons for the failure:
        - The patch fixed the issue, but altered the original code's behavior.
        - The patch was too aggressive and removed or altered necessary code.
        - The patch did not adhere to the original code's logic.
        - There exists better patch locations that can fix the issue without introducing regressions.
        """
    )
    empty_patch_prompt = inspect.cleandoc(
        """
        The patch did not apply, here are some possible reasons:
        - Trying to patch a file that does not exist in the repository.
        - Trying to patch fuzzer or harness related file. (These files are used to test the validity of the patch.)
        - Incorrect patch format. (Focus on the patch formatting instructions.)
        """
    )
    sarif_location_template = inspect.cleandoc(
        """
        <sarif_report>
        Detected a potential issue in the codebase:
        - Physical Location: {physical_location}
        - Logical Locations: {logical_locations}
        - Message: {message}
        - Kind: {kind}
        - Severity: {severity}
        </sarif_report>
        """
    )
    sarif_no_value_prompt = "Not available"
    related_diff_template = inspect.cleandoc(
        """
        <related_diff>
        The following diff may be related to the initial issue:
        ```
        {related_diff}
        ```
        If the diff is not related to the current issue, you can ignore it.
        </related_diff>
        """
    )
    diff_header_regex = re.compile(r"^(?:--- |\+\+\+ |@@).*$", re.MULTILINE)

    def __init__(self, llm: BaseChatModel) -> None:
        super().__init__(llm)
        self.context: AgentContext | None = None
        self.detection: Detection | None = None
        self.max_n_log_chars = 16000

    def set_context_and_detection(
        self, context: AgentContext, detection: Detection
    ) -> None:
        self.context = context
        self.detection = detection

    def _environment_run_pov(self) -> Action:
        if self.context is None or self.detection is None:
            raise ValueError("Context and detection must be provided")
        environment = self.context["pool"].restore(self.context)
        try:
            environment.run_pov(self.context, self.detection)
        except ChallengePoVFoundError as e:
            return VulnerableDiffAction(diff=b"", stdout=e.stdout, stderr=e.stderr)
        except Exception as e:  # pylint: disable=broad-except
            return UnknownErrorAction(error=e)
        return SoundDiffAction(diff=b"")

    def __call__(self, state: EvaluationTeamState) -> dict[str, Any]:
        if self.context is None or self.detection is None:
            raise ValueError("Context and detection must be provided")

        if state.patch_status == PatchStatus.INITIALIZED:
            # NOTE: Handle cases that may not have restored.
            self.context["pool"].restore(self.context)

            action = self._environment_run_pov()
            # Sarif only case
            if (
                not isinstance(action, VulnerableDiffAction)
                and self.detection.sarif_report is not None
            ):
                action = VulnerableDiffAction(diff=b"", stdout=b"", stderr=b"")
        elif state.diff == "":
            action = UncompilableDiffAction(
                variant="uncompilable",
                diff=b"",
                stdout=b"",
                stderr=b"Patch not applicable due to empty diff",
            )
        else:
            action = self.context["evaluator"].evaluate(
                self.context, bytes(state.diff, "utf-8"), self.detection
            )
            self.context["pool"].restore(self.context)

        patch_status = PatchStatus.from_action(action)
        repo_lang = self.language_map[self.detection.language]
        patch_result = self._add_sarif_logs(
            self._filter_action_log(
                (
                    getattr(action, "stdout", b"") + getattr(action, "stderr", b"")
                ).decode(errors="replace"),
                repo_lang,
                patch_status,
            )
        )
        if state.issue == "":
            state.issue = self._add_related_diff(patch_result)

        tests_log = ""
        if patch_status == PatchStatus.SOUND:
            # TODO: Add test logs in the issue. (Currently too long to naively add)
            tests_log, patch_status = self._environment_run_tests(
                state.diff, patch_status
            )
            self.context["pool"].restore(self.context)
            if patch_status == PatchStatus.TESTS_FAILED:
                patch_result = self.internal_tests_failure_prompt
        elif patch_status == PatchStatus.COMPILABLE:
            if "no tests" in patch_result:
                # NOTE: Some issues have "no tests" this is a hard-coded workaround to avoid such cases.
                patch_status = PatchStatus.SOUND
            else:
                # NOTE: Otherwise, COMPILABLE is the test failure case.
                patch_status = PatchStatus.TESTS_FAILED
                patch_result = self.internal_tests_failure_prompt
        elif patch_status == PatchStatus.UNCOMPILABLE and state.diff == "":
            # If the patch is empty, provide a more informative message
            patch_result = self.empty_patch_prompt

        if "logger" in self.context:
            log = (
                f"===Evaluator Result===\n{patch_status}\n"
                + f"===Evaluator Diff===\n{state.diff}\n"
                + f"===Patch Result===\n{patch_result}\n"
                + f"===Issue===\n{state.issue}\n"
                + f"===Evaluation Report===\n{state.evaluation_report}\n"
                + f"===Analysis Report===\n{state.analysis_report}\n"
            )
            if patch_status == PatchStatus.SOUND:
                if tests_log == "Tests skipped. No tests found.":
                    log += "===Tests Result===\nNo tests found\n"
                elif tests_log == "Command interaction error while testing.":
                    log += (
                        "===Tests Result===\nCommand interaction error while testing\n"
                    )
                else:
                    log += "===Tests Result===\nPassed\n"
            elif patch_status == PatchStatus.TESTS_FAILED:
                log += "===Tests Result===\nFailed\n"
            log += "===Evaluation End==="
            self.context["logger"].info(log)
        return {
            "patch_status": patch_status,
            "issue": state.issue,
            "patch_result": patch_result,
            "diff": state.diff,
            "repo_lang": repo_lang,
            "tests_log": tests_log,
        }

    def _filter_vulnerable_log(self, action_log: str, lang: str) -> str:
        if len(action_log) <= self.max_n_log_chars:
            return action_log
        vulnerability_prefix = None
        vulnerability_postfix = None
        if lang in ("c", "cpp"):
            vulnerability_prefix = "====="
            vulnerability_postfix = "==ABORTING"
        elif lang == "java":
            vulnerability_prefix = "== Java Exception:"
            vulnerability_postfix = "== libFuzzer crashing input =="

        if vulnerability_prefix is not None and vulnerability_prefix in action_log:
            action_log = (
                vulnerability_prefix
                + action_log.split(vulnerability_prefix, maxsplit=1)[1]
            )

        if vulnerability_postfix is not None and vulnerability_postfix in action_log:
            action_log = (
                action_log.rsplit(vulnerability_postfix, maxsplit=1)[0]
                + vulnerability_postfix
            )
            # Reduce token usage by removing shadow bytes log
            shadow_bytes_text = "Shadow bytes around the buggy address:"
            if shadow_bytes_text in action_log:
                action_log = action_log.split(shadow_bytes_text, maxsplit=1)[0]

        if len(action_log) > self.max_n_log_chars:
            action_log = self.abbreviated_log_template.format(
                log=action_log[: self.max_n_log_chars]
            )
        return action_log

    def _filter_uncompilable_log(self, action_log: str, lang: str) -> str:
        if len(action_log) <= self.max_n_log_chars:
            return action_log
        build_failure_prefix = None
        build_failure_postfix = None
        if lang in ("c", "cpp"):
            build_failure_prefix = "error:"
            build_failure_postfix = "errors generated."
        elif lang == "java":
            build_failure_prefix = "ERROR"
            build_failure_postfix = "For more information about the errors"

        if build_failure_prefix is not None and build_failure_prefix in action_log:
            log_before_prefix, log_after_prefix = action_log.split(
                build_failure_prefix, maxsplit=1
            )
            # Add the whole line before the prefix
            prefix = build_failure_prefix
            if "\n" in log_before_prefix:
                prefix = log_before_prefix.rsplit("\n", maxsplit=1)[1] + prefix
            action_log = prefix + log_after_prefix
        if build_failure_postfix is not None and build_failure_postfix in action_log:
            action_log = (
                action_log.rsplit(build_failure_postfix, maxsplit=1)[0]
                + build_failure_postfix
            )
        if len(action_log) > self.max_n_log_chars:
            action_log = self.abbreviated_log_template.format(
                log=action_log[: self.max_n_log_chars]
            )
        return action_log

    def _filter_java_timeout_log(self, action_log: str) -> str:
        # Filter out timeout logs without helpful crash stacks.
        if "ERROR: libFuzzer: timeout" not in action_log:
            return action_log

        if self.context is None or self.detection is None:
            return action_log

        try:
            if get_crash_stacks(self.context, self.detection) is not None:
                return action_log

            # Reoccuring trace are abbreviated
            timeout_stack_bytes = JVMTimeoutStacktraceAnalyzer().analyze(
                self.context, self.detection
            )
            if timeout_stack_bytes is None:
                return action_log
        except Exception as e:
            if "logger" in self.context:
                self.context["logger"].info(
                    f"Evaluator: JVMTimeoutStacktraceAnalyzer failed: {e}",
                    exc_info=True,
                )
            return action_log

        timeout_stack_str = timeout_stack_bytes.decode(errors="replace")
        return "ERROR: libFuzzer: timeout\n" + timeout_stack_str

    def _filter_java_stackoverflow_log(self, action_log: str) -> str:
        # Filter out timeout logs without helpful crash stacks.
        if "FuzzerSecurityIssueLow: Stack overflow" not in action_log:
            return action_log

        if self.context is None or self.detection is None:
            return action_log

        try:
            if get_crash_stacks(self.context, self.detection) is not None:
                return action_log

            overflow_stack = JVMStackOverflowStacktraceAnalyzer().analyze(
                self.context, self.detection
            )
            if overflow_stack is None:
                return action_log
        except Exception as e:
            if "logger" in self.context:
                self.context["logger"].info(
                    f"Evaluator: JVMStackOverflowStacktraceAnalyzer failed: {e}",
                    exc_info=True,
                )
            return action_log

        action_log = "FuzzerSecurityIssue: Stack overflow\n" + overflow_stack
        # Abbreviate the log if it is too long
        if len(action_log) > self.max_n_log_chars:
            visible_len = self.max_n_log_chars // 2
            action_log = (
                action_log[:visible_len] + "\n...\n" + action_log[-visible_len:]
            )
        return action_log

    def _filter_action_log(
        self, action_log: str, lang: str, patch_status: PatchStatus
    ) -> str:
        if action_log == "":
            return action_log
        # This is a hard coded filtering for the oss-fuzz logs
        if patch_status == PatchStatus.VULNERABLE:
            if lang == "java":
                action_log = self._filter_java_timeout_log(action_log)
                action_log = self._filter_java_stackoverflow_log(action_log)

            action_log = self._filter_vulnerable_log(action_log, lang)
        elif patch_status == PatchStatus.UNCOMPILABLE:
            action_log = self._filter_uncompilable_log(action_log, lang)

        if len(action_log) > self.max_n_log_chars and not action_log.endswith(
            "[TRUNCATED]"
        ):
            action_log = self.abbreviated_log_template.format(
                log=action_log[: self.max_n_log_chars]
            )

        # Prevent crash logs instructing LLM to allow network connections (#1007)
        action_log = action_log.replace(
            "If the fuzz test is expected to perform network connections,"
            " call com.code_intelligence.jazzer.api.BugDetectors#allowNetworkConnections"
            " at the beginning of your fuzz test and optionally provide a predicate matching the expected hosts.",
            "",
        )
        return action_log

    def _add_sarif_logs(self, action_log: str) -> str:
        if self.context is None or self.detection is None:
            return action_log
        sarif_report: SarifReport | None = self.detection.sarif_report
        if sarif_report is None:
            return action_log
        if sarif_report.runs is None or len(sarif_report.runs) == 0:
            return action_log

        sarif_logs: list[str] = []
        for sarif_run in sarif_report.runs:
            if sarif_run.results is None or len(sarif_run.results) == 0:
                continue
            for result in sarif_run.results:
                formatted_sarif_result = self._format_sarif_result(result)
                if formatted_sarif_result == "":
                    continue
                else:
                    sarif_logs.append(formatted_sarif_result)

        return action_log + "\n" + "\n".join(sarif_logs)

    def _format_sarif_result(self, sarif_result: Result) -> str:
        if sarif_result.locations is None or len(sarif_result.locations) == 0:
            return ""

        formatted_sarif_locations: list[str] = []
        for location in sarif_result.locations:
            physical_location_prompt = self.sarif_no_value_prompt
            logical_locations_prompt = self.sarif_no_value_prompt
            message_prompt = self.sarif_no_value_prompt
            kind_prompt = self.sarif_no_value_prompt
            severity_prompt = self.sarif_no_value_prompt

            # Physical Location
            if (
                location.physicalLocation is not None
                and location.physicalLocation.root.artifactLocation is not None
                and location.physicalLocation.root.artifactLocation.uri is not None
            ):
                file_path = location.physicalLocation.root.artifactLocation.uri

                line_start = location.physicalLocation.root.region.root.startLine  # type: ignore
                line_end = location.physicalLocation.root.region.root.endLine  # type: ignore
                if isinstance(line_start, int) and isinstance(line_end, int):
                    physical_location_prompt = f"{file_path}:{line_start}-{line_end}"
                else:
                    physical_location_prompt = file_path

            # Logical Location
            if (
                location.logicalLocations is not None
                and len(location.logicalLocations) > 0
            ):
                logical_locations: list[str] = []
                for logical_location in location.logicalLocations:
                    loc_prompt = ""
                    if logical_location.name is not None:
                        loc_prompt += logical_location.name
                    if logical_location.kind is not None:
                        loc_prompt += f"({logical_location.kind})"
                    if loc_prompt != "":
                        logical_locations.append(loc_prompt)
                if len(logical_locations) > 0:
                    logical_locations_prompt = ", ".join(logical_locations)

            # Message
            if (
                sarif_result.message.root.text is not None
                and sarif_result.message.root.text != ""
            ):
                message_prompt = sarif_result.message.root.text

            # Kind
            if sarif_result.kind is not None:
                kind_prompt = str(sarif_result.kind)

            # Severity
            if sarif_result.level is not None:
                severity_prompt = str(sarif_result.level)

            formatted_sarif_locations.append(
                self.sarif_location_template.format(
                    physical_location=physical_location_prompt,
                    logical_locations=logical_locations_prompt,
                    message=message_prompt,
                    kind=kind_prompt,
                    severity=severity_prompt,
                )
            )
        return "\n".join(formatted_sarif_locations)

    def _add_related_diff(self, issue: str) -> str:
        if self.context is None or self.detection is None:
            return issue
        if not isinstance(self.detection.mode, AIxCCChallengeDeltaMode):
            return issue
        try:
            delta_diffs = get_all_diff(self.context, self.detection)
        except Exception as e:
            if "logger" in self.context:
                self.context["logger"].info(
                    f"Prism evaluator: get_all_diff failed: {e}",
                    exc_info=True,
                )
            return issue

        if delta_diffs is None or len(delta_diffs) == 0:
            return issue

        # delta_diffs is a list of tuples (commit, diff)
        delta_diffs_concat = "\n".join(d[1] for d in delta_diffs)

        # diffs containing "aixcc" are filtered out
        diffs = delta_diffs_concat.split("diff --git")
        valid_diffs = [d for d in diffs if "aixcc" not in d and d.strip() != ""]

        if len(valid_diffs) == 0:
            return issue

        related_diff = "\n".join(valid_diffs)
        if len(related_diff) > self.max_n_log_chars:
            related_diff_not_abbr_part = related_diff[: self.max_n_log_chars]
            diff_headers = self.diff_header_regex.findall(
                related_diff[self.max_n_log_chars :]
            )
            diff_headers = [dh for dh in diff_headers if isinstance(dh, str)]
            if len(diff_headers) == 0:
                related_diff = related_diff_not_abbr_part + "\n..."
            else:
                diff_headers_with_abbr: list[str] = []
                for header in diff_headers:
                    if header.startswith("---"):
                        diff_headers_with_abbr.append("...")
                    diff_headers_with_abbr.append(header)
                related_diff_abbr_part = "\n".join(diff_headers_with_abbr)
                if len(related_diff_abbr_part) > self.max_n_log_chars:
                    related_diff_abbr_part = related_diff_abbr_part[
                        : self.max_n_log_chars
                    ]
                related_diff = (
                    related_diff_not_abbr_part + "\n" + related_diff_abbr_part + "\n..."
                )

        related_diff = related_diff.strip()
        if related_diff == "":
            return issue

        return (
            issue + "\n" + self.related_diff_template.format(related_diff=related_diff)
        )

    def _environment_run_tests(
        self, diff: str, current_patch_status: PatchStatus
    ) -> tuple[str, PatchStatus]:
        if self.context is None or self.detection is None:
            raise ValueError("Context and detection must be provided")
        if current_patch_status != PatchStatus.SOUND:
            return "Tests skipped. Provide a sound patch.", current_patch_status

        try:
            if not self.context["pool"].internal_test_exists():
                return "Tests skipped. No tests found.", current_patch_status

            environment = self.context["pool"].restore(self.context)
            environment.patch(self.context, diff.encode("utf-8", errors="replace"))
            stdout, _ = environment.run_tests(self.context)
            tests_log = stdout
        except ChallengeTestFailedError as e:
            tests_log = (e.stdout + e.stderr).decode(errors="replace")
            current_patch_status = PatchStatus.TESTS_FAILED
        except CommandInteractionError:
            tests_log = "Command interaction error while testing."
            # NOTE: Since we cannot decide if tests failed or not, we assume the patch is sound.
            current_patch_status = PatchStatus.SOUND
        except TimeoutExpired as e:
            tests_log = (e.stdout + e.stderr).decode(errors="replace")
            current_patch_status = PatchStatus.TESTS_FAILED
        return tests_log, current_patch_status
