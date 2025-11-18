import json
import re
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple, cast

from python_aixcc_challenge.detection.models import AIxCCChallengeDeltaMode
from python_llm.api.actors import LlmApiManager
from unidiff import PatchSet

from crete.atoms.detection import Detection
from crete.commons.crash_analysis.contexts import CrashAnalyzerContext
from crete.commons.crash_analysis.functions import get_crash_stacks
from crete.commons.interaction.exceptions import CommandInteractionError
from crete.commons.interaction.functions import run_command
from crete.commons.logging.contexts import LoggingContext
from crete.framework.agent.contexts import AgentContext
from crete.framework.analyzer.services.call_trace import CallTraceAnalyzer
from crete.framework.analyzer.services.call_trace.models import FunctionCall
from crete.framework.analyzer.services.commit.models import (
    FunctionDiffInfo,
    LLMCommitAnalysis,
    PatchInfo,
)
from crete.framework.analyzer.services.commit.scripts import (
    CALL_STACK_VULNERABILITY_ANALYSIS_SYSTEM_PROMPT,
    CALL_STACK_VULNERABILITY_ANALYSIS_USER_PROMPT,
    COMMIT_ANALYZER_MAX_TOKEN,
    DEFAULT_SANITIZER_PROMPT,
)
from crete.framework.environment.functions import get_pov_results
from crete.framework.evaluator.contexts import EvaluatingContext

MAX_TOTAL_PATCH_DIFF_LENGTH = 10000


def _process_hunk_lines(hunk_lines: List[str], context_lines: int) -> List[str]:
    if not hunk_lines:
        return []

    processed_lines: List[str] = [hunk_lines[0]]

    content_lines = hunk_lines[1:]
    if not content_lines:
        return processed_lines

    change_indices = [
        i
        for i, line in enumerate(content_lines)
        if line.startswith("+") or line.startswith("-")
    ]

    if not change_indices:
        if context_lines > 0:
            keep_max = min(len(content_lines), 2 * context_lines)
        else:
            keep_max = min(len(content_lines), 1) if len(content_lines) > 0 else 0
        processed_lines.extend(content_lines[:keep_max])
        return processed_lines

    lines_to_keep_indices: Set[int] = set()
    for index in change_indices:
        start = max(0, index - context_lines)
        end = min(len(content_lines) - 1, index + context_lines)
        for i in range(start, end + 1):
            lines_to_keep_indices.add(i)

    if lines_to_keep_indices:
        sorted_indices = sorted(list(lines_to_keep_indices))

        last_kept_index = -1
        for current_index in sorted_indices:
            if last_kept_index != -1 and current_index > last_kept_index + 1:
                if not processed_lines[-1].strip().endswith("..."):
                    processed_lines.append("...\\n")

            processed_lines.append(content_lines[current_index])
            last_kept_index = current_index

    if (
        not any(
            line.startswith("+") or line.startswith("-") for line in processed_lines[1:]
        )
        and change_indices
    ):
        first_change_line_index = change_indices[0]
        if not any(
            content_lines[first_change_line_index] in pl for pl in processed_lines
        ):
            if first_change_line_index > 0 and (
                not lines_to_keep_indices or min(lines_to_keep_indices, default=-1) > 0
            ):
                if not processed_lines[-1].strip().endswith("..."):
                    processed_lines.append("...\\n")
            processed_lines.append(content_lines[first_change_line_index])

    return processed_lines


def shrink_diff(diff_content: str, context_lines: int = 3) -> str:
    processed_hunks: List[str] = []
    current_hunk_lines: List[str] = []
    header_lines: List[str] = []
    body_started = False
    first_hunk = True

    lines = diff_content.splitlines(True)

    for _, line in enumerate(lines):
        if not body_started:
            header_lines.append(line)
            if line.startswith("+++ "):
                body_started = True
            continue

        if body_started:
            if line.startswith("@@"):
                if current_hunk_lines:
                    processed_hunk_content = _process_hunk_lines(
                        current_hunk_lines, context_lines
                    )
                    if len(processed_hunk_content) > 1 or (
                        first_hunk and processed_hunk_content
                    ):
                        processed_hunks.extend(processed_hunk_content)
                        first_hunk = False
                current_hunk_lines = [line]
            else:
                current_hunk_lines.append(line)

    if current_hunk_lines:
        processed_hunk_content = _process_hunk_lines(current_hunk_lines, context_lines)
        if len(processed_hunk_content) > 1 or (first_hunk and processed_hunk_content):
            processed_hunks.extend(processed_hunk_content)

    if not processed_hunks:
        return "".join(header_lines) if header_lines else ""

    return "".join(header_lines) + "".join(processed_hunks)


def _calculate_total_diff_length(patches: List[PatchInfo]) -> int:
    """Calculates the total character length of all diff_content in the patches."""
    total_length = 0
    for patch in patches:
        total_length += len(patch.diff_content)
    return total_length


def truncate_with_token_constraint(output: str, max_token: int) -> str:
    if len(output) <= max_token:
        return output
    else:
        summary_template = (
            "\n... (output truncated, showing first {} and last {} characters) ...\n"
        )
        summary_length = len(summary_template.format("0000", "0000"))
        available_content_length = max_token - summary_length - 10
        half_length = available_content_length // 2
        if half_length <= 0:
            return output[:max_token]
        start_output = output[:half_length]
        end_output = output[-half_length:]
        summary_message = summary_template.format(len(start_output), len(end_output))
        truncated_output = f"{start_output}{summary_message}{end_output}"
        if len(truncated_output) > max_token:
            truncated_output = truncated_output[:max_token]
        return truncated_output


def run_git_command(
    context: LoggingContext, command: str, git_repo_path: Path
) -> str | None:
    assert command.startswith("git"), "Command must start with 'git'"
    try:
        if not git_repo_path.exists():
            raise FileNotFoundError(
                f"Git repository path does not exist: {git_repo_path}"
            )
        stdout, _ = run_command((command, git_repo_path))
        return stdout
    except TypeError as e:
        context["logger"].error(f"During Github Command, Type error: {str(e)}")
        return None
    except FileNotFoundError as e:
        context["logger"].error(
            f"During Github Command, File not found error: {str(e)}"
        )
        return None
    except CommandInteractionError as e:
        context["logger"].error(
            f"During Github Command, Command interaction error: {str(e)}"
        )
        return None


def get_all_diff(
    context: EvaluatingContext, detection: Detection
) -> List[Tuple[str, str]] | None:
    src_dir = context["pool"].source_directory
    assert isinstance(detection.mode, AIxCCChallengeDeltaMode), (
        "Detection mode is not AIxCCChallengeDeltaMode"
    )
    base_ref = detection.mode.base_ref
    delta_ref = detection.mode.delta_ref
    assert base_ref is not None and delta_ref is not None, (
        "Base ref or delta ref is None"
    )
    output = run_git_command(
        context, f"git rev-list --reverse {base_ref}..{delta_ref}", src_dir
    )
    if not output:
        return None
    commits = output.splitlines()
    result: List[Tuple[str, str]] = []
    for commit in commits:
        diff = run_git_command(context, f"git diff {commit}^ {commit}", src_dir)
        if diff:
            result.append((commit, diff))
    return result


def get_ref_diff(context: EvaluatingContext, detection: Detection) -> str | None:
    all_diff = get_all_diff(context, detection)
    if all_diff is None:
        return None

    assert len(all_diff) == 1

    ref_diff = all_diff[0][1]

    # Filter out .aixcc/ directory.
    # This only exists in our development environment. It will not exist in the AFC.
    filtered_patch_set = PatchSet([])
    for patched_file in PatchSet.from_string(ref_diff):
        if ".aixcc" in str(patched_file.path):
            continue
        filtered_patch_set.append(patched_file)

    return str(filtered_patch_set)


def parse_call_stack_from_sanitizer(
    context: AgentContext,
    detection: Detection,
) -> List[Tuple[str, str, int]] | None:
    crash_analyzer_context = CrashAnalyzerContext(context)
    crash_stacks = get_crash_stacks(crash_analyzer_context, detection)
    if not crash_stacks:
        return None
    call_stack_array: List[Tuple[str, str, int]] = []
    calee_function_name = "__crash_lines__"
    src_dir = context["pool"].source_directory
    for crash_stack in crash_stacks:
        for _, frame in crash_stack.iter_relevant_frames():
            host_file_path = frame.file
            if host_file_path.is_relative_to(src_dir):
                file_path = host_file_path.relative_to(src_dir)
                line_number = frame.line
                call_stack_array.append(
                    (calee_function_name, str(file_path), line_number)
                )
            calee_function_name = frame.function_name
    return call_stack_array


def get_call_stack_array_from_call_trace(
    call_trace: List[FunctionCall],
) -> List[Tuple[str, str, int]]:
    call_stack_array: List[Tuple[str, str, int]] = []
    for func_call in call_trace:
        if func_call.callee_file is not None:
            call_stack_array.append(
                (
                    func_call.callee_name,
                    str(func_call.callee_file),
                    func_call.call_line,
                )
            )
    return call_stack_array


def get_call_stack_array(
    context: AgentContext, detection: Detection
) -> List[Tuple[str, str, int]] | None:
    call_trace = CallTraceAnalyzer().analyze(context, detection, simple=True)
    if call_trace:
        return get_call_stack_array_from_call_trace(call_trace)
    else:
        return parse_call_stack_from_sanitizer(context, detection)


def function_diff_in_files(
    context: AgentContext,
    git_repo_path: Path,
    base_ref: str,
    delta_ref: str,
    file_paths: List[str],
) -> List[FunctionDiffInfo]:
    function_diff_list: List[FunctionDiffInfo] = []
    for file_path in file_paths:
        command = f"git diff -p -W {base_ref} {delta_ref} -- '{file_path}'"
        diff_output = run_git_command(context, command, git_repo_path)
        if not diff_output or "Binary files" in diff_output:
            continue
        diffs = parse_diff_output_to_function_diffs(diff_output, file_path)
        function_diff_list.extend(diffs)
    return function_diff_list


def parse_diff_output_to_function_diffs(
    diff_output: str, file_path: str
) -> List[FunctionDiffInfo]:
    function_diff_list: List[FunctionDiffInfo] = []
    header = ""
    for line in diff_output.splitlines():
        if line.startswith("diff ") or line.startswith("---") or line.startswith("+++"):
            header += line + "\n"
    chunks = re.split(r"\n(?=@@)", diff_output)
    for chunk in chunks:
        if not chunk.startswith("@@"):
            continue
        hunk_header_match = re.search(
            r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", chunk
        )
        if not hunk_header_match:
            continue
        original_start = int(hunk_header_match.group(1))
        original_count = int(hunk_header_match.group(2) or "1")
        new_start = int(hunk_header_match.group(3))
        new_count = int(hunk_header_match.group(4) or "1")
        original_end = original_start + original_count - 1
        new_end = new_start + new_count - 1
        lines = chunk.split("\n")
        has_changes = any(
            line.startswith("+") or line.startswith("-") for line in lines[1:]
        )
        if has_changes:
            if header and header.strip() not in chunk:
                chunk_with_header = header + chunk
            else:
                chunk_with_header = chunk
            function_diff_list.append(
                FunctionDiffInfo(
                    file_path=file_path,
                    original_line_span=(original_start, original_end),
                    new_line_span=(new_start, new_end),
                    diff=chunk_with_header,
                )
            )
    return function_diff_list


def extract_file_paths_from_call_stack_array(
    call_stack_array: List[Tuple[str, str, int]],
) -> List[str]:
    file_paths: List[str] = []
    for _, file_path, _ in call_stack_array:
        if file_path not in file_paths:
            file_paths.append(file_path)
    return file_paths


def extract_patches_from_relevant_function(
    context: AgentContext,
    detection: Detection,
    function_diffs: List[FunctionDiffInfo],
    call_stack_array: List[Tuple[str, str, int]],
) -> List[PatchInfo]:
    patches: List[PatchInfo] = []
    for diff_info in function_diffs:
        file_path = diff_info.file_path
        original_start, original_end = diff_info.original_line_span
        new_start, new_end = diff_info.new_line_span
        diff_content = diff_info.diff
        relevant = False
        relevant_function = ""
        for function_name, call_file_path, line_num in call_stack_array:
            if call_file_path == file_path and new_start <= line_num <= new_end:
                relevant = True
                relevant_function = function_name
                break
        if relevant:
            header_text = f"Changes to code in file '{file_path}' (lines {original_start}-{original_end} -> {new_start}-{new_end})"
            patch = PatchInfo(
                file_path=file_path,
                function_name=relevant_function,
                diff_content=diff_content,
                header=header_text,  # Renamed variable to avoid conflict with import
            )
            patches.append(patch)
    return patches


def extract_patches_from_relevant_call_stack(
    context: AgentContext,
    detection: Detection,
    call_stack_array: List[Tuple[str, str, int]],
) -> List[PatchInfo] | None:
    assert isinstance(detection.mode, AIxCCChallengeDeltaMode), (
        "Detection mode is not AIxCCChallengeDeltaMode"
    )
    base_ref = detection.mode.base_ref
    delta_ref = detection.mode.delta_ref
    assert base_ref is not None and delta_ref is not None, (
        "Base ref or delta ref is None"
    )
    file_paths = extract_file_paths_from_call_stack_array(call_stack_array)
    function_diffs = function_diff_in_files(
        context,
        context["pool"].source_directory,
        base_ref,
        delta_ref,
        file_paths,
    )
    return extract_patches_from_relevant_function(
        context,
        detection,
        function_diffs,
        call_stack_array,
    )


def get_function_patches(
    context: AgentContext,
    detection: Detection,
    call_stack_array: List[Tuple[str, str, int]],
) -> List[PatchInfo] | None:
    function_patches_orig = extract_patches_from_relevant_call_stack(
        context, detection, call_stack_array
    )

    if function_patches_orig is None:
        return None

    if not function_patches_orig:
        return []

    unit_name = "characters"
    initial_total_length = _calculate_total_diff_length(function_patches_orig)

    if initial_total_length <= MAX_TOTAL_PATCH_DIFF_LENGTH:
        context["logger"].info(
            f"Total original diff content {unit_name} ({initial_total_length}) is within limit ({MAX_TOTAL_PATCH_DIFF_LENGTH}). No shrinking needed."
        )
        return function_patches_orig

    context["logger"].info(
        f"Total original diff content {unit_name} ({initial_total_length}) "
        + f"exceeds limit ({MAX_TOTAL_PATCH_DIFF_LENGTH}). Applying shrink_diff."
    )

    shrunk_patches: List[PatchInfo] = []
    for patch in function_patches_orig:
        shrunk_content = shrink_diff(patch.diff_content)
        shrunk_patches.append(
            PatchInfo(
                file_path=patch.file_path,
                function_name=patch.function_name,
                diff_content=shrunk_content,
                header=patch.header,
            )
        )

    current_total_length_after_shrink = _calculate_total_diff_length(shrunk_patches)

    if current_total_length_after_shrink > MAX_TOTAL_PATCH_DIFF_LENGTH:
        context["logger"].info(
            f"Total diff content {unit_name} ({current_total_length_after_shrink}) after shrink_diff still "
            + f"exceeds limit ({MAX_TOTAL_PATCH_DIFF_LENGTH}). Attempting to truncate patches further."
        )

        final_trimmed_patches: List[PatchInfo] = []
        accumulated_length = 0
        for patch_to_trim in shrunk_patches:
            patch_len = len(patch_to_trim.diff_content)

            if accumulated_length + patch_len <= MAX_TOTAL_PATCH_DIFF_LENGTH:
                final_trimmed_patches.append(patch_to_trim)
                accumulated_length += patch_len
            else:
                remaining_budget = MAX_TOTAL_PATCH_DIFF_LENGTH - accumulated_length
                if remaining_budget > 0:
                    final_truncated_content = patch_to_trim.diff_content[
                        :remaining_budget
                    ]
                    if final_truncated_content:
                        final_truncated_patch = PatchInfo(
                            file_path=patch_to_trim.file_path,
                            function_name=patch_to_trim.function_name,
                            diff_content=final_truncated_content,
                            header=patch_to_trim.header,
                        )
                        final_trimmed_patches.append(final_truncated_patch)
                        accumulated_length += len(final_truncated_content)
                break

        function_patches_to_return = final_trimmed_patches
        final_length = _calculate_total_diff_length(function_patches_to_return)
        context["logger"].info(
            f"Patches further truncated. Original total {unit_name} (before shrink): {initial_total_length}, "
            + f"After shrink {unit_name}: {current_total_length_after_shrink}, New total {unit_name}: {final_length} (Limit: {MAX_TOTAL_PATCH_DIFF_LENGTH})"
        )
    else:
        function_patches_to_return = shrunk_patches
        context["logger"].info(
            f"Applied shrink_diff. Original total {unit_name}: {initial_total_length}, "
            + f"New total {unit_name} after shrink: {current_total_length_after_shrink} (Limit: {MAX_TOTAL_PATCH_DIFF_LENGTH})"
        )

    return function_patches_to_return


def search_commit_by_patches(
    patches: List[PatchInfo], all_diff: List[Tuple[str, str]]
) -> List[PatchInfo]:
    expanded_patches: List[PatchInfo] = []
    included_commits: Set[str] = set()
    filtered_patches = patches
    patch_identifiers: Set[Tuple[str, str]] = set()
    for patch_in_loop in filtered_patches:  # Renamed variable
        patch_identifiers.add((patch_in_loop.file_path, patch_in_loop.function_name))
    for commit_hash, diff_content in all_diff:
        for file_path, function_name in patch_identifiers:
            if file_path in diff_content or function_name in diff_content:
                if commit_hash not in included_commits:
                    expanded_patch = PatchInfo(
                        commit_hash=commit_hash, diff_content=diff_content
                    )
                    expanded_patches.append(expanded_patch)
                    included_commits.add(commit_hash)
                break
    if not expanded_patches:
        return filtered_patches
    return expanded_patches


def convert_all_diff_to_patches(all_diff: List[Tuple[str, str]]) -> List[PatchInfo]:
    patches: List[PatchInfo] = []
    for commit_hash, diff_content in all_diff:
        patch = PatchInfo(
            commit_hash=commit_hash,
            diff_content=diff_content,
            header=f"Commit: {commit_hash}",
        )
        patches.append(patch)
    return patches


def format_patches_to_string(patches: List[PatchInfo]) -> str:
    return "".join(str(patch) for patch in patches)


def get_prompts_from_pov_results(context: AgentContext, detection: Detection) -> str:
    environment = context["pool"].use(context, "DEBUG")
    assert environment is not None, "Environment is None"
    pov_results = get_pov_results(
        environment=environment, context=context, detection=detection
    )
    if pov_results:
        stdout, _ = pov_results
        return str(stdout)
    else:
        return DEFAULT_SANITIZER_PROMPT


def make_user_prompt_for_commit_analysis(
    sanitizer_prompt: str,
    patches: List[PatchInfo],
) -> str:
    patches_str = format_patches_to_string(patches)
    sanitizer_prompt = truncate_with_token_constraint(
        sanitizer_prompt, COMMIT_ANALYZER_MAX_TOKEN // 3
    )
    patches_str = truncate_with_token_constraint(
        patches_str, COMMIT_ANALYZER_MAX_TOKEN // 3 * 2
    )
    user_prompt = CALL_STACK_VULNERABILITY_ANALYSIS_USER_PROMPT.format(
        sanitizer_prompt=sanitizer_prompt, combined_patches=patches_str
    )
    user_prompt = truncate_with_token_constraint(user_prompt, COMMIT_ANALYZER_MAX_TOKEN)
    return user_prompt


def get_response_json_from_llm(
    context: AgentContext,
    llm_api_manager: LlmApiManager,
    system_prompt: str,
    user_prompt: str,
) -> Any | None:
    try:
        chat_model = llm_api_manager.langchain_litellm()
        response = chat_model.invoke(
            [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {"role": "user", "content": user_prompt},
            ]
        )
        response_text = str(getattr(response, "content", "") or "")
        json_match = re.search(r"```json\s*(.*?)\s*```", response_text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1).strip()
            try:
                return json.loads(json_str)
            except json.JSONDecodeError as direct_json_err:
                context["logger"].warning(
                    f"Failed to parse extracted JSON: {direct_json_err}. Raw extracted: {json_str}"
                )
        try:
            return json.loads(response_text)
        except json.JSONDecodeError as main_json_err:
            context["logger"].error(
                f"JSON parsing error for the whole response: {str(main_json_err)}. Response text: {response_text}"
            )
            return None
    except ConnectionError as conn_err:
        context["logger"].error(f"Connection error with LLM API: {str(conn_err)}")
        return None
    except Exception as e:
        context["logger"].error(
            f"Unexpected error in get_response_json_from_llm: {str(e)}"
        )
        return None


def make_commit_analyze_from_response_json(
    response_json_data: Any,
) -> List[LLMCommitAnalysis]:
    result_list: List[Dict[str, Any]] = []
    if isinstance(response_json_data, dict):
        result_list = [response_json_data]
    elif isinstance(response_json_data, list):
        typed_list_data = cast(List[Any], response_json_data)
        result_list = [item for item in typed_list_data if isinstance(item, dict)]
    else:
        return []
    analyze_results: List[LLMCommitAnalysis] = []
    result: Dict[str, Any]
    for result in result_list:
        vul_type = str(result.get("vulnerability_type", "unknown"))
        severity = float(result.get("severity", 0.0))
        description = str(result.get("description", ""))
        description = description.replace("\\n", "\n")
        recommendation = str(result.get("recommendation", ""))
        problem_lines = None
        if "problematic_lines" in result and isinstance(
            result["problematic_lines"], list
        ):
            lines = cast(List[Any], result["problematic_lines"])
            problem_lines = [str(line) for line in lines if line is not None]
        patches_to_avoid = None
        if "patches_to_avoid" in result and isinstance(
            result["patches_to_avoid"], list
        ):
            patches_data = cast(
                List[Any], result["patches_to_avoid"]
            )  # Renamed to avoid conflict
            patches_to_avoid = [
                str(p_data) for p_data in patches_data if p_data is not None
            ]
        analyze_results.append(
            LLMCommitAnalysis(
                vulnerability_type=vul_type,
                severity=severity,
                description=description,
                recommendation=recommendation,
                problematic_lines=problem_lines,
                patches_to_avoid=patches_to_avoid,
                raw_response=json.dumps(response_json_data),
            )
        )
    analyze_results.sort(key=lambda x: x.severity, reverse=True)
    return analyze_results


def llm_commit_analyze(
    llm_api_manager: LlmApiManager,
    context: AgentContext,
    detection: Detection,
    patches: List[PatchInfo],
    sanitizer_prompt: str,
) -> List[LLMCommitAnalysis] | None:
    if not patches:
        return None
    response_data = get_response_json_from_llm(
        context,
        llm_api_manager,
        CALL_STACK_VULNERABILITY_ANALYSIS_SYSTEM_PROMPT,
        make_user_prompt_for_commit_analysis(sanitizer_prompt, patches),
    )
    if response_data is None:
        return None
    return make_commit_analyze_from_response_json(response_data)


def get_call_stack_relevant_patches(
    context: AgentContext,
    detection: Detection,
) -> List[PatchInfo] | None:
    relevant_patches: List[PatchInfo] | None = None
    all_diff_obj_for_patches: List[Tuple[str, str]] | None = None
    try:
        all_diff_obj_for_patches = get_all_diff(context, detection)
    except NameError:
        context["logger"].warning("get_all_diff function not found or not imported.")
    except Exception as e:
        context["logger"].warning(
            f"Error getting initial_diff_info: {e}", exc_info=True
        )

    last_call_stack_data: List[Tuple[str, str, int]] | None = None
    try:
        call_stack_array = parse_call_stack_from_sanitizer(context, detection)
        if call_stack_array is not None:
            last_call_stack_data = list(call_stack_array)
    except NameError:
        context["logger"].warning(
            "get_call_stack_array function not found or not imported."
        )

    try:
        relevant_patches = get_function_patches(
            context, detection, last_call_stack_data if last_call_stack_data else []
        )
        if not relevant_patches and all_diff_obj_for_patches:
            relevant_patches = convert_all_diff_to_patches(all_diff_obj_for_patches)

    except NameError:
        context["logger"].warning(
            "One or more functions for get_call_stack_relevant_patches not found or not imported."
        )

    return relevant_patches


def analyze_commit_by_llm(
    context: AgentContext,
    detection: Detection,
    llm_api_manager: LlmApiManager,
) -> List[LLMCommitAnalysis] | None:
    """
    Analyze the commit by LLM.

    Args:
        context: The context of the agent.
        detection: The detection object.
        llm_api_manager: The LLM API manager.
    """

    relevant_patches = get_call_stack_relevant_patches(context, detection)
    if not relevant_patches:
        context["logger"].warning(
            "Skipping llm_commit_analyze: no patches could be determined."
        )
        return None
    sanitizer_prompt_for_llm = get_prompts_from_pov_results(context, detection)
    llm_analysis_result = llm_commit_analyze(
        llm_api_manager=llm_api_manager,
        context=context,
        detection=detection,
        patches=relevant_patches,
        sanitizer_prompt=sanitizer_prompt_for_llm,
    )
    if llm_analysis_result is not None:
        return llm_analysis_result

    return None
