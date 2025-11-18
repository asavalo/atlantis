import inspect
import re
from typing import Any, Dict

from python_aixcc_challenge.detection.models import AIxCCChallengeDeltaMode
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as SarifReport,
)
from sarif.sarif_model import Result

from crete.atoms.action import (
    Action,
    CompilableDiffAction,
    NoPatchAction,
    SoundDiffAction,
    UncompilableDiffAction,
    UnknownErrorAction,
    VulnerableDiffAction,
    WrongDiffAction,
)
from crete.atoms.detection import Detection
from crete.commons.crash_analysis.functions import get_crash_stacks
from crete.commons.interaction.exceptions import CommandInteractionError, TimeoutExpired
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.multi_retrieval.nodes.base_node import BaseNode
from crete.framework.agent.services.multi_retrieval.states.patch_state import (
    PatchAction,
    PatchState,
    PatchStatus,
    format_patches_to_str,
)
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


class DockerEvaluator(BaseNode):
    internal_tests_failure_prompt: str = inspect.cleandoc(
        """\
        Here are your patches that has fixed the issue but failed to pass the internal tests:
        {patches}
        ---
        Here are some possible reasons for internal tests failure:
        - The patch has fixed the issue but altered the behavior of the code.
        - The patch was too aggressive and removed or altered the necessary code.
        - There exists better patch locations that can fix the issue.
        """
    )
    uncompilable_diff_prompt: str = inspect.cleandoc(
        """\
        {original_issue}
        ---
        Here are your patches that was applied but failed to compile:
        {patches}
        ---
        Here are some possible reasons for uncompilable patches:
        - Incorrect patch format or line ranges.
        - Incorrect indentation, whitespace or newline characters.
        - Omitted or abbreviated contents.
        - Redundant text around the patching code.
        - Overlapping line ranges to multiple patches.
        - Some patches were trying to patch a file that does not exist in the repository.
        - Some patches have incorrect patch format.
        """
    )
    empty_diff_prompt: str = inspect.cleandoc(
        """\
        {original_issue}
        ---
        Here are some possible reasons for empty patch:
        - Trying to patch a file that does not exist in the repository.
        - Trying to patch fuzzer or harness related files. (These files are used to test the validity of the patch.)
        - There exists better patch locations that can fix the issue.
        - Incorrect patch format. (Focus on the patch formatting instructions.)
        """
    )
    abbreviated_log_template: str = inspect.cleandoc(
        """\
        {log}
        ...
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
    related_diff_prompt = inspect.cleandoc(
        """
        {issue}
        ---
        The following diff may be related to the initial issue:
        ```
        {related_diff}
        ```
        If the diff is not related to the current issue, you can ignore it.
        """
    )
    language_map = {
        "c": "c",
        "c++": "cpp",
        "cpp": "cpp",
        "java": "java",
        "jvm": "java",
    }
    diff_header_regex = re.compile(r"^(?:--- |\+\+\+ |@@).*$", re.MULTILINE)

    def __init__(
        self,
        context: AgentContext | None = None,
        detection: Detection | None = None,
        max_n_evals: int = 3,
        max_n_log_chars: int = 16000,
    ) -> None:
        self.context = context
        self.detection = detection
        self.max_n_evals = max_n_evals
        self.max_n_log_chars = max_n_log_chars

    def set_context_and_detection(
        self, context: AgentContext, detection: Detection
    ) -> None:
        self.context = context
        self.detection = detection

    def _map_action_to_status(self, action: Action) -> PatchStatus:
        patch_status = PatchStatus.INITIALIZED
        match action:
            case UncompilableDiffAction():
                patch_status = PatchStatus.UNCOMPILABLE
            case CompilableDiffAction():
                patch_status = PatchStatus.COMPILABLE
            case VulnerableDiffAction():
                patch_status = PatchStatus.VULNERABLE
            case WrongDiffAction():
                patch_status = PatchStatus.WRONG
            case SoundDiffAction():
                patch_status = PatchStatus.SOUND
            case UnknownErrorAction():
                patch_status = PatchStatus.UNKNOWN
            case NoPatchAction():
                patch_status = PatchStatus.UNCOMPILABLE
            case _:
                raise ValueError(f"Unknown action type: {type(action)}")
        return patch_status

    def _get_action_log(self, action: Action) -> str:
        action_log = getattr(action, "stdout", b"") + getattr(action, "stderr", b"")
        return action_log.decode(errors="replace")

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
                    f"DockerEvaluator: JVMTimeoutStacktraceAnalyzer failed: {e}",
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
                    f"DockerEvaluator: JVMStackOverflowStacktraceAnalyzer failed: {e}",
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

    def _filter_action_log(self, action_log: str, lang: str) -> str:
        # This is a hard coded filtering for the oss-fuzz logs
        # Jave specific logs
        if lang == "java":
            action_log = self._filter_java_timeout_log(action_log)
            action_log = self._filter_java_stackoverflow_log(action_log)

        # Vulnerability logs
        vulnerability_prefix = None
        vulnerability_postfix = None
        if lang in ("c", "cpp"):
            vulnerability_prefix = "====="
            vulnerability_postfix = "==ABORTING"
        elif lang == "java":
            vulnerability_prefix = "== Java Exception:"
            vulnerability_postfix = "== libFuzzer crashing input =="

        is_vulnerability_log = False
        if vulnerability_prefix is not None and vulnerability_prefix in action_log:
            action_log = (
                vulnerability_prefix
                + action_log.split(vulnerability_prefix, maxsplit=1)[1]
            )
            is_vulnerability_log = True
        if vulnerability_postfix is not None and vulnerability_postfix in action_log:
            action_log = (
                action_log.rsplit(vulnerability_postfix, maxsplit=1)[0]
                + vulnerability_postfix
            )
            # Reduce token usage by removing shadow bytes log
            shadow_bytes_text = "Shadow bytes around the buggy address:"
            if shadow_bytes_text in action_log:
                action_log = action_log.split(shadow_bytes_text, maxsplit=1)[0]
            is_vulnerability_log = True

        # Prevent crash logs instructing LLM to allow network connections (#1007)
        action_log = action_log.replace(
            "If the fuzz test is expected to perform network connections,"
            " call com.code_intelligence.jazzer.api.BugDetectors#allowNetworkConnections"
            " at the beginning of your fuzz test and optionally provide a predicate matching the expected hosts.",
            "",
        )

        if is_vulnerability_log:
            if len(action_log) > self.max_n_log_chars:
                action_log = self.abbreviated_log_template.format(
                    log=action_log[: self.max_n_log_chars]
                )
            return action_log

        # Build failure logs
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

    def _add_additional_issue(
        self, issue: str, patch_status: PatchStatus, diff: str, formatted_patches: str
    ) -> str:
        if patch_status == PatchStatus.UNCOMPILABLE:
            if diff == "":
                issue = self.empty_diff_prompt.format(original_issue=issue)
            else:
                issue = self.uncompilable_diff_prompt.format(
                    original_issue=issue, patches=formatted_patches
                )
        return issue

    def _add_sarif_logs(self, issue: str) -> str:
        if self.context is None or self.detection is None:
            return issue
        sarif_report: SarifReport | None = self.detection.sarif_report
        if sarif_report is None:
            return issue
        if sarif_report.runs is None or len(sarif_report.runs) == 0:
            return issue

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

        if issue == "":
            return "\n".join(sarif_logs)
        elif len(sarif_logs) == 0:
            return issue
        return issue + "\n" + "\n".join(sarif_logs)

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
                    f"DockerEvaluator: get_all_diff failed: {e}",
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

        return self.related_diff_prompt.format(issue=issue, related_diff=related_diff)

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

    def _environment_run_tests(
        self, diff: str, current_patch_status: PatchStatus
    ) -> tuple[str, PatchStatus]:
        if self.context is None or self.detection is None:
            raise ValueError("Context and detection must be provided")
        if current_patch_status != PatchStatus.SOUND:
            return "Tests skipped. Provide a sound patch.", current_patch_status

        if not self.context["pool"].internal_test_exists():
            return "Tests skipped. No tests found.", current_patch_status

        environment = self.context["pool"].restore(self.context)
        environment.patch(self.context, bytes(diff, "utf-8"))

        try:
            stdout, _ = environment.run_tests(self.context)
            tests_log = stdout
        except ChallengeTestFailedError as e:
            tests_log = (e.stdout + e.stderr).decode(errors="replace")
            current_patch_status = PatchStatus.TESTS_FAILED
        except TimeoutExpired as e:
            tests_log = (e.stdout + e.stderr).decode(errors="replace")
            current_patch_status = PatchStatus.TESTS_FAILED
        return tests_log, current_patch_status

    def __call__(self, state: PatchState) -> Dict[str, Any]:
        if self.context is None or self.detection is None:
            raise ValueError("Context and detection must be provided")

        if state.patch_action != PatchAction.EVALUATE:
            raise NotImplementedError(
                f"Action {state.patch_action} is not supported for {self.__class__.__name__}"
            )

        state.n_evals += 1
        if state.diff == "":
            if state.n_evals == 1:
                # NOTE: Handle cases that may not have restored.
                self.context["pool"].restore(self.context)

                action = self._environment_run_pov()
                # Sarif only case
                if (
                    not isinstance(action, VulnerableDiffAction)
                    and self.detection.sarif_report is not None
                ):
                    action = VulnerableDiffAction(diff=b"", stdout=b"", stderr=b"")
            elif state.n_evals < self.max_n_evals:
                action = UncompilableDiffAction(
                    variant="uncompilable",
                    diff=b"",
                    stdout=b"",
                    stderr=b"Patch not applicable due to empty diff",
                )
            else:
                action = NoPatchAction()
        else:
            action = self.context["evaluator"].evaluate(
                self.context, bytes(state.diff, "utf-8"), self.detection
            )
            self.context["pool"].restore(self.context)

        patch_status = self._map_action_to_status(action)
        action_log = self._get_action_log(action)
        repo_lang = self.language_map[self.detection.language]
        issue = self._filter_action_log(action_log, repo_lang)
        formatted_patches = format_patches_to_str(state.applied_patches)
        issue = self._add_additional_issue(
            issue, patch_status, state.diff, formatted_patches
        )
        issue = self._add_sarif_logs(issue)

        # We only handle related diffs for delta mode on the first evaluation for token efficiency.
        if state.n_evals == 1:
            issue = self._add_related_diff(issue)

        tests_log = ""
        if patch_status == PatchStatus.UNKNOWN:
            patch_action = PatchAction.DONE
        elif patch_status == PatchStatus.SOUND:
            patch_action = PatchAction.DONE
            try:
                tests_log, patch_status = self._environment_run_tests(
                    state.diff, patch_status
                )
                self.context["pool"].restore(self.context)
            except CommandInteractionError:
                tests_log = "Command interaction error while testing."
                patch_status = PatchStatus.TESTS_FAILED
            if patch_status == PatchStatus.TESTS_FAILED:
                patch_action = PatchAction.ANALYZE_ISSUE
                issue = self.internal_tests_failure_prompt.format(
                    patches=formatted_patches
                )
                # NOTE: CommandInteractionError often occurs while testing. Finish in this case.
                if "Command interaction error" in tests_log:
                    patch_action = PatchAction.DONE
        elif patch_status == PatchStatus.COMPILABLE:
            patch_action = PatchAction.ANALYZE_ISSUE
            issue = self.internal_tests_failure_prompt.format(patches=formatted_patches)
            # NOTE: Some issues have "no tests" this is a hard-coded workaround to avoid such cases
            if "no tests" in action_log:
                patch_action = PatchAction.DONE
        else:
            patch_action = PatchAction.ANALYZE_ISSUE

        if state.n_evals >= self.max_n_evals:
            patch_action = PatchAction.DONE

        if state.n_evals > 1 and "logger" in self.context:
            self.context["logger"].info(
                "===DockerEvaluator Result===\n"
                + f"n evals:{state.n_evals}, {patch_status}\n"
                + f"===DockerEvaluator Diff===\n{state.diff}\n"
                + f"===DockerEvaluator Issue===\n{issue}\n"
                + "===DockerEvaluator End==="
            )
        return {
            "patch_action": patch_action,
            "patch_status": patch_status,
            "n_evals": state.n_evals,
            "issue": issue,
            "repo_lang": repo_lang,
            "diff": state.diff,
            "tests_log": tests_log,
        }
