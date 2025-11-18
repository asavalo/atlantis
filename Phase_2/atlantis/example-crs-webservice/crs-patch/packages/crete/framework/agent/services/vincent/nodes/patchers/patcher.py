from pathlib import Path
from typing import Any, Optional

from langgraph.graph import (  # pylint: disable=import-error, no-name-in-module
    END,
)
from python_file_system.directory.context_managers import changed_directory
from python_llm.api.actors import LlmApiManager

from crete.atoms.action import (
    CompilableDiffAction,
    SoundDiffAction,
    UncompilableDiffAction,
    VulnerableDiffAction,
)
from crete.atoms.detection import Detection
from crete.commons.interaction.functions import run_command
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.functions import store_debug_file
from crete.framework.agent.services.vincent.functions import (
    create_prompt,
    extract_patches_from_chat,
    extract_requests_in_chat,
    get_last_chat,
    send_and_update_llm,
)
from crete.framework.agent.services.vincent.nodes.llm_node import LLMNode
from crete.framework.agent.services.vincent.nodes.patchers.models import (
    PatchFailure,
    PatchSegment,
)
from crete.framework.agent.services.vincent.states.patch_state import (
    PatchStage,
    PatchState,
)

PATCH_REPORT_PATTERN = "# Patch Report"
PATCH_RETRY_COUNT = 10


def _run_git_diff(file_path: Path) -> str:
    stdout, _ = run_command((f"git diff {file_path}", Path(".")))
    # If you want to make it stateless, you can use the following code.
    # run_command((f"git restore {file_path}", Path(".")))
    return stdout


def _unify_diffs(diffs: list[str]) -> bytes:
    return "\n".join(diffs).encode("utf-8")


def _verify_line_nums(cur_line: int, total_line_cnt: int, patch: PatchSegment) -> bool:
    if patch.start_line < cur_line:
        return False

    if patch.start_line > patch.end_line:
        return False

    if patch.start_line > total_line_cnt:
        return False

    if patch.end_line > total_line_cnt:
        return False

    return True


def _search_lines_and_replace(
    original_src: str, patches: list[PatchSegment]
) -> str | None:
    original_lines = original_src.splitlines(keepends=True)
    original_line_cnt = len(original_lines)

    original_lines = [""] + original_lines

    # sort the patches by the order of patch location
    patches = sorted(patches, key=lambda x: x.start_line)

    patched_blocks: list[str] = []

    cur_line = 1
    for patch in patches:
        if not _verify_line_nums(cur_line, original_line_cnt, patch):
            return None

        prev_block = "".join(original_lines[cur_line : patch.start_line])

        patched_blocks.append(prev_block)
        patched_blocks.append(patch.patch_code)

        cur_line = patch.end_line + 1

    # merge the rest of original blocks
    if cur_line < len(original_lines):
        patched_blocks.append("".join(original_lines[cur_line:]))

    patched_src = "".join(patched_blocks)

    return patched_src


class Patcher(LLMNode):
    def __init__(self, llm_api_manager: LlmApiManager):
        super().__init__(llm_api_manager)
        self.is_instructed = False
        self.patch_history: set[bytes] = set()

    def __call__(self, state: PatchState) -> dict[str, Any]:
        if state.patch_stage != PatchStage.PATCH:
            raise RuntimeError

        assert state.detection is not None

        if not self.is_instructed:
            self._instruct_llm_with_guideline(state)
            return self._get_dict_from_state(state)

        assert len(state.requests) == 0

        patch_diff = self._generate_patch_diff(state)

        # New LLM requests can be identified due to fixed responses from the LLM.
        if len(state.requests) != 0:
            return self._get_dict_from_state(state)

        if patch_diff is None:
            state.patch_stage = PatchStage.DONE
            return self._get_dict_from_state(state)

        state.diff = patch_diff

        store_debug_file(
            self.context,
            f"patch-{state.feedback_cnt}.diff",
            state.diff.decode(errors="replace"),
            log_output=False,
        )

        state.action = self.context["evaluator"].evaluate(
            self.context, state.diff, state.detection
        )

        self.context["logger"].info(f"patch result: {state.action.__class__.__name__}")

        return self._finalize_patch(state)

    def _say_fix_patch_report(self, state: PatchState):
        send_and_update_llm(
            self.context,
            state.messages,
            self.llm,
            create_prompt("fix_patch_report"),
        )

        state.requests += extract_requests_in_chat(get_last_chat(state.messages))

    def _finalize_patch(self, state: PatchState) -> dict[str, Any]:
        assert self.is_instructed

        self.is_instructed = False

        # @NOTE: The following lines will be changed after feedback nodes are introduced
        if isinstance(state.action, SoundDiffAction):
            state.patch_stage = PatchStage.DONE
            return self._get_dict_from_state(state)

        store_debug_file(
            self.context,
            f"patch-try-result-{state.feedback_cnt}.txt",
            (
                getattr(state.action, "stdout", b"")
                + getattr(state.action, "stderr", b"")
            ).decode(errors="replace"),
            log_output=False,
        )

        state.feedback_cnt += 1

        if isinstance(state.action, VulnerableDiffAction):
            state.patch_stage = PatchStage.VULNERABLE_FEEDBACK
            return self._get_dict_from_state(state)
        elif isinstance(state.action, UncompilableDiffAction):
            state.patch_stage = PatchStage.COMPILE_FEEDBACK
            return self._get_dict_from_state(state)
        elif isinstance(state.action, CompilableDiffAction):
            state.patch_stage = PatchStage.TEST_FEEDBACK
            return self._get_dict_from_state(state)

        state.patch_stage = PatchStage.DONE
        return self._get_dict_from_state(state)

    def set_context_and_detection(self, context: AgentContext, detection: Detection):
        self.context = context
        self.detection = detection

    def _instruct_llm_with_guideline(self, state: PatchState):
        self.context["logger"].info("******* Patch Phase *******")

        send_and_update_llm(
            self.context,
            state.messages,
            self.llm,
            create_prompt("proceed_to_patch_step"),
        )

        state.requests += extract_requests_in_chat(get_last_chat(state.messages))

        self.is_instructed = True

    def _get_diff_from_patches_dict(
        self, patches_dict: dict[str, list[PatchSegment]]
    ) -> tuple[Optional[bytes], Optional[list[PatchFailure]]]:
        diffs: list[str] = []
        for src_relpath, patches in patches_dict.items():
            self.context["logger"].info(f'patching "{src_relpath}" file...')

            patch_diff = self._apply_patches_and_get_diff(src_relpath, patches)

            if patch_diff is None:
                return (
                    None,
                    [
                        PatchFailure(
                            invalid_segments=patches,
                            reason="Running git apply command failed.",
                        )
                    ],
                )

            # the diff changed nothing from the original source code.
            if patch_diff == "":
                return (
                    None,
                    [
                        PatchFailure(
                            invalid_segments=patches,
                            reason="Your patch segment(s) changes nothing from the original source code. You must provide patch segments that modifies the original source code to fix the given bug.",
                        )
                    ],
                )

            diffs.append(patch_diff)

        result_diff = _unify_diffs(diffs)

        if result_diff in self.patch_history:
            return (
                None,
                [
                    PatchFailure(
                        invalid_segments=[],
                        reason="You just submitted an identical patch to the previous one. You must provide a different patch for every patching attempts. If you have no choice but to generate the identical patch, analyze the project again and identify the completely different root cause that can explain the issue. Then, provide me with a full patch report with a different approach.",
                    )
                ],
            )
        self.patch_history.add(result_diff)

        return (result_diff, None)

    def _verify_patch_segments(
        self, patch_segments: list[PatchSegment]
    ) -> list[PatchFailure]:
        failures: list[PatchFailure] = []

        for i in range(len(patch_segments)):
            cur_segment = patch_segments[i]

            filepath = self.context["pool"].source_directory / cur_segment.filename

            if not filepath.exists():
                failures.append(
                    PatchFailure(
                        invalid_segments=[cur_segment],
                        reason=f'Patch target file (`{cur_segment.filename}`) in "{cur_segment.patch_tag}" does not follow the rule. Make sure that `filename` in each segment is valid and relative to the target repository. Use the "filepath" information obtained by the previous [REQUEST:type] requests as the ground truth.',
                    )
                )
                continue

            # prevent from patching the file that contains "fuzz"
            if any(
                fuzz_keyword in cur_segment.filename
                for fuzz_keyword in ["fuzz", "FUZZ", "Fuzz"]
            ):
                failures.append(
                    PatchFailure(
                        invalid_segments=[cur_segment],
                        reason=f'The patch target file (`{cur_segment.filename}`) in "{cur_segment.patch_tag}" seems to be related to the fuzzing component. The patch target file must not be a fuzzer-related or test-related code. Refer to the "Patch Generation" again and find another way to fix the issue.',
                    )
                )
                continue

            # prevent from patching fuzzing-related code"
            if any(
                fuzz_keyword in cur_segment.patch_code
                for fuzz_keyword in ["fuzz", "FUZZ", "Fuzz"]
            ):
                failures.append(
                    PatchFailure(
                        invalid_segments=[cur_segment],
                        reason=f'The content of the segment "{cur_segment.patch_tag}" contains the fuzzing-related code. You **MUST NOT** use fuzzer-specific patches (even the fuzzer-specific comments are disallowed). Refer to the "Patch Generation" again and find another root cause to fix the issue.',
                    )
                )
                continue

            total_line_cnt = len(
                filepath.read_text(encoding="utf-8", errors="ignore").splitlines(
                    keepends=True
                )
            )

            if cur_segment.start_line > cur_segment.end_line:
                failures.append(
                    PatchFailure(
                        invalid_segments=[cur_segment],
                        reason=f'The start line number ({cur_segment.start_line}) in the "{cur_segment.patch_tag}" is greater than the end line number ({cur_segment.end_line}).',
                    )
                )
                continue

            if cur_segment.end_line > total_line_cnt:
                failures.append(
                    PatchFailure(
                        invalid_segments=[cur_segment],
                        reason=f'The line number ({cur_segment.end_line}) in "{cur_segment.patch_tag}" exceeds the total line count ({total_line_cnt}) of `{cur_segment.filename}`.',
                    )
                )
                continue

            if i == len(patch_segments) - 1:
                break

            next_segment = patch_segments[i + 1]
            if next_segment.start_line <= cur_segment.end_line:
                # line overlap found, it's an invalid patch report
                failures.append(
                    PatchFailure(
                        invalid_segments=[cur_segment, next_segment],
                        reason=f'The patch segment "{cur_segment.patch_tag}" (end line: {cur_segment.end_line}) overlaps the next segment "{next_segment.patch_tag}" (start line: {next_segment.start_line}).',
                    )
                )
                continue

        return failures

    def _try_patch_generation(
        self, state: PatchState
    ) -> tuple[Optional[bytes], Optional[list[PatchFailure]]]:
        last_response = get_last_chat(state.messages)

        if PATCH_REPORT_PATTERN not in last_response:
            return (
                None,
                [
                    PatchFailure(
                        invalid_segments=[],
                        reason=f'The pattern "{PATCH_REPORT_PATTERN}" is not found in your response. You must contain "{PATCH_REPORT_PATTERN}" in the head of the report. If you cannot provide a new patch, find the root cause from a completely different aspect than you previously thought.',
                    )
                ],
            )

        if "[/PATCH]" in last_response:
            return (
                None,
                [
                    PatchFailure(
                        invalid_segments=[],
                        reason='Do *NOT* use "[/PATCH]" to close each patch segment. Check the "Patch Segments" section again.',
                    )
                ],
            )

        patches_per_srcfile = extract_patches_from_chat(last_response)

        if patches_per_srcfile is None:
            return (
                None,
                [
                    PatchFailure(
                        invalid_segments=[],
                        reason='No valid patch segment with valid tags not found in the report. Check the "Patch Segments" section again.',
                    )
                ],
            )

        patch_failures: list[PatchFailure] = []
        for _, patch_segments in patches_per_srcfile.items():
            patch_failures += self._verify_patch_segments(patch_segments)

        if len(patch_failures) != 0:
            return (None, patch_failures)

        return self._get_diff_from_patches_dict(patches_per_srcfile)

    def _notify_llm_patch_errors(self, state: PatchState, failures: list[PatchFailure]):
        send_and_update_llm(
            self.context,
            state.messages,
            self.llm,
            _construct_patch_fix_prompt(failures),
        )

        state.requests += extract_requests_in_chat(get_last_chat(state.messages))

    def _generate_patch_diff(self, state: PatchState) -> bytes | None:
        assert self.is_instructed
        assert len(state.requests) == 0

        patch_diff = None
        for i in range(PATCH_RETRY_COUNT):
            if len(state.requests) != 0:
                self.context["logger"].info(
                    "New requests are identified by the fixed LLM response"
                )
                return None

            self.context["logger"].info(f"patch generation llm try: {i}")
            patch_diff, failures = self._try_patch_generation(state)

            if failures:
                self.context["logger"].info("notify LLM with report format errors...")
                self._notify_llm_patch_errors(state, failures)
                continue

            assert patch_diff
            break

        store_debug_file(
            self.context,
            f"patch-report-{state.feedback_cnt}.txt",
            get_last_chat(state.messages),
            log_output=False,
        )

        return patch_diff

    def _apply_patches_and_get_diff(
        self, src_relpath: str, patches: list[PatchSegment]
    ) -> str | None:
        filepath: Path = self.context["pool"].source_directory / src_relpath

        original_src = filepath.read_text(encoding="utf-8", errors="replace")

        patched_src = _search_lines_and_replace(original_src, patches)

        if patched_src is None:
            self.context["logger"].error(
                f'Failed to generate patched source for "{src_relpath}"'
            )
            return None

        filepath.write_text(patched_src)

        with changed_directory(self.context["pool"].source_directory):
            diff = _run_git_diff(Path(src_relpath))

        self.context["pool"].restore(self.context)
        return diff


def route_patcher(state: PatchState) -> str:
    match state.patch_stage:
        case PatchStage.INIT_ANALYSIS:
            pass
        case PatchStage.ANALYZE_ROOT_CAUSE:
            pass
        case PatchStage.ANALYZE_PROPERTY:
            pass
        case PatchStage.PATCH:
            return "request_handler"
        case PatchStage.COMPILE_FEEDBACK:
            return "compile_feedback"
        case PatchStage.VULNERABLE_FEEDBACK:
            return "vulnerable_feedback"
        case PatchStage.TEST_FEEDBACK:
            return "test_feedback"
        case PatchStage.DONE:
            return END

    raise ValueError(f"{state.patch_stage} is not allowd for the patch stage")


def _construct_patch_fix_prompt(failures: list[PatchFailure]) -> str:
    prompt = "Your previous patch report is invalid due to the following reason(s):\n\n"

    for failure in failures:
        prompt += "* " + failure.reason + "\n"

    prompt += '\nRefer to the "Patch Generation" section and submit the fixed report.\n'

    return prompt
