import re
import hashlib
from pathlib import Path
from typing import Literal, TypedDict, Optional, List, Union, cast
import subprocess

from crete.framework.environment.functions import resolve_project_path
from crete.atoms.path import DEFAULT_CACHE_DIRECTORY

from ..models import FunctionCall


class CallLine(TypedDict):
    type: Literal["Call"]
    file: Path
    line: int
    caller: str
    callee: str | Literal["<unknown>"]


class EntryLine(TypedDict):
    type: Literal["Entry"]
    file: Path
    function: str
    line: int


def _generate_log_hash(log_content: str, length: int = 8) -> str:
    """Generates a short hash for the log content."""
    return hashlib.sha256(log_content.encode("utf-8")).hexdigest()[:length]


def _parse_shell_output_line(line: str) -> Optional[tuple[str, str, str]]:
    if not line.strip():
        return None
    parts = line.split(",", 2)
    if len(parts) == 3:
        parsed_callee_name = parts[0].strip()
        original_callee_file_str = parts[1].strip()
        callee_line_number_str = parts[2].strip()
        return parsed_callee_name, original_callee_file_str, callee_line_number_str
    else:
        print(
            f"Warning: Could not parse shell output line (expected 3 parts for Entry log): {line}"
        )
        return None


def _resolve_callee_file_path(
    original_callee_file_str: str, source_directory: Path
) -> Path:
    resolved_callee_file_path = resolve_project_path(
        Path(original_callee_file_str), source_directory
    )
    if resolved_callee_file_path:
        try:
            return resolved_callee_file_path.relative_to(source_directory)
        except ValueError:
            return resolved_callee_file_path
    return Path(original_callee_file_str)


def _simple_parse_from_shell_output(
    shell_output: str, source_directory: Path
) -> List[FunctionCall]:
    call_trace: List[FunctionCall] = []
    lines = shell_output.strip().split("\n")
    for line in lines:
        parsed_line_parts = _parse_shell_output_line(line)
        if not parsed_line_parts:
            continue

        parsed_callee_name, original_callee_file_str, callee_line_number_str = (
            parsed_line_parts
        )

        callee_file_rel = _resolve_callee_file_path(
            original_callee_file_str, source_directory
        )

        callee_def_line_num = 0
        try:
            callee_def_line_num = int(callee_line_number_str)
        except ValueError:
            print(
                f"Warning: Could not parse line number: {callee_line_number_str} in line: {line}"
            )

        function_call_obj = FunctionCall(
            caller_file=Path("."),
            caller_name="",
            call_line=callee_def_line_num,
            callee_file=callee_file_rel,
            callee_name=parsed_callee_name,
        )
        call_trace.append(function_call_obj)

    return call_trace


def simple_parse_call_trace_log_for_c(
    log_content_for_hash: str,
    source_directory: Path,
    full_log_to_save: str,
) -> List[FunctionCall]:
    log_hash = _generate_log_hash(log_content_for_hash)

    try:
        cache_sub_dir = DEFAULT_CACHE_DIRECTORY / "call_trace"
        cache_sub_dir.mkdir(parents=True, exist_ok=True)
        log_file_path = cache_sub_dir / f"{log_hash}.log"

        lines_to_save_list = full_log_to_save.split("\n")

        with open(log_file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines_to_save_list))
        print(f"Simple mode: Call trace log saved to: {log_file_path.resolve()}")

    except OSError as e:
        print(f"Error saving call trace log in simple_parse: {e}")
        return []

    filename_for_shell = log_file_path.as_posix()

    grep_entry_cmd = f"grep -E '^\\[Entry\\]' \"{filename_for_shell}\""
    sed_cmd = "sed -E -n 's/^\\[Entry\\] Function: ([^,]+), File: ([^,]+), Line: ([0-9]+).*/\\1,\\2,\\3/p'"
    tac_cmd = "tac"
    awk_cmd = "awk '!seen[$0]++'"

    shell_command = f"{grep_entry_cmd} | {sed_cmd} | {tac_cmd} | {awk_cmd} | {tac_cmd}"

    try:
        process = subprocess.run(
            shell_command,
            shell=True,
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
        )
        shell_output = process.stdout
        return _simple_parse_from_shell_output(shell_output, source_directory)
    except subprocess.CalledProcessError as e:
        print(f"Shell command failed with error code {e.returncode}: {e}")
        print(f"Stderr: {e.stderr}")
        return []
    except Exception as e:
        print(f"An unexpected error occurred during shell command execution: {e}")
        return []


def parse_call_trace_log_for_c(
    call_trace_log: str,
    source_directory: Path,
    simple: bool = False,
) -> List[FunctionCall]:
    """
    Example:
    [Call] File: ./../samples/mock_vp.c, Line: 162, Caller: run_main, Callee: menu
    [Entry] Function: menu, File: ./../samples/mock_vp.c, Line: 53
    [Call] File: ./../samples/mock_vp.c, Line: 54, Caller: menu, Callee: printf
    [Call] File: ./../samples/mock_vp.c, Line: 55, Caller: menu, Callee: printf
    """

    if simple:
        return simple_parse_call_trace_log_for_c(
            log_content_for_hash=call_trace_log,
            source_directory=source_directory,
            full_log_to_save=call_trace_log,
        )

    try:
        cache_dir = DEFAULT_CACHE_DIRECTORY
        cache_dir.mkdir(parents=True, exist_ok=True)
        classic_cache_file_path = cache_dir / "call_trace.log"

        lines_to_save = call_trace_log.split("\n")

        with open(classic_cache_file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines_to_save))
        print(
            f"Classic mode: Call trace log saved to: {classic_cache_file_path.resolve()} (all lines saved)"
        )
    except Exception as e:
        print(f"Error saving call trace log to cache (classic mode): {e}")

    log_lines = call_trace_log.strip().split("\n")

    print(f"Parsing all {len(log_lines)} lines of the call trace log (classic mode).")

    call_trace: List[FunctionCall] = []
    if len(log_lines) < 2:
        return []

    for i in range(len(log_lines) - 1):
        line_data_parsed = _parse_line(source_directory, log_lines[i])
        next_line_data_parsed = _parse_line(source_directory, log_lines[i + 1])

        if line_data_parsed is None or next_line_data_parsed is None:
            continue

        if line_data_parsed.get("type") == "Call":
            if not all(
                key in line_data_parsed for key in ("file", "line", "caller", "callee")
            ):
                continue

            line_data_as_call = cast(CallLine, line_data_parsed)

            callee_name = _get_callee_name(line_data_as_call, next_line_data_parsed)
            if callee_name is None:
                continue

            if "file" not in next_line_data_parsed:
                continue

            resolved_caller_file = line_data_as_call["file"]
            resolved_callee_file = next_line_data_parsed["file"]

            try:
                caller_file_rel = resolved_caller_file.relative_to(source_directory)
                callee_file_rel = resolved_callee_file.relative_to(source_directory)
            except ValueError:
                continue

            call_trace.append(
                FunctionCall(
                    caller_file=caller_file_rel,
                    caller_name=line_data_as_call["caller"],
                    call_line=line_data_as_call["line"],
                    callee_file=callee_file_rel,
                    callee_name=callee_name,
                )
            )

    return call_trace


def _parse_line(
    source_directory: Path, line: str
) -> Optional[Union[CallLine, EntryLine]]:
    call_match = re.match(
        r"^\[Call\] File: (.+), Line: (\d+), Caller: (.+), Callee: (.+)$", line
    )
    if call_match:
        file_str, line_str, caller, callee = call_match.groups()
        resolved_file = resolve_project_path(Path(file_str), source_directory)
        if not resolved_file:
            return None
        try:
            return CallLine(
                type="Call",
                file=resolved_file,
                line=int(line_str) - 1,
                caller=caller,
                callee=callee,
            )
        except ValueError:
            return None

    entry_match = re.match(r"^\[Entry\] Function: (.+), File: (.+), Line: (\d+)$", line)
    if entry_match:
        function, file_str, line_str = entry_match.groups()
        resolved_file = resolve_project_path(Path(file_str), source_directory)
        if not resolved_file:
            return None
        try:
            return EntryLine(
                type="Entry",
                function=function,
                file=resolved_file,
                line=int(line_str) - 1,
            )
        except ValueError:
            return None
    return None


def _get_callee_name(
    line_data: CallLine, next_line_data: Union[CallLine, EntryLine]
) -> Optional[str]:
    callee_name = None
    next_type = next_line_data.get("type")

    if next_type == "Call":
        next_caller = next_line_data.get("caller")
        if next_caller is not None and (
            line_data["callee"] == next_caller or line_data["callee"] == "<unknown>"
        ):
            callee_name = next_caller
    elif next_type == "Entry":
        callee_name = next_line_data.get("function")
    return callee_name
