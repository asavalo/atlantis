import re
import glob
import hashlib
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from crete.framework.analyzer.services.call_trace.models import FunctionCall
from crete.framework.environment.functions import resolve_project_path
from crete.atoms.path import DEFAULT_CACHE_DIRECTORY

JVM_FUNCTION_INVOKE_REGEX = "^\\[Invoke\\] caller class: (.*), caller method: (.*), callee class: (.*), callee method: (.*), file: (.*), line: ([-+]?[0-9]+)$"


def _generate_log_hash(log_content: str, length: int = 8) -> str:
    return hashlib.sha256(log_content.encode("utf-8")).hexdigest()[:length]


def _create_path_map(source_directory: Path) -> list[Path]:
    return list(
        map(
            lambda file: Path(file),
            glob.glob("**/*.java", root_dir=source_directory, recursive=True),
        )
    )


def _package_to_path(
    path_map: list[Path], source_directory: Path, package: str, file_name: str
) -> Optional[Path]:
    file_path = Path(*package.split(".")) / file_name

    resolved_path_candidates = list(
        filter(
            lambda f: str(f).endswith(str(file_path)),
            path_map,
        )
    )

    if len(resolved_path_candidates) > 0:
        resolved_path = resolve_project_path(
            resolved_path_candidates[0], source_directory
        )
        if resolved_path is not None and resolved_path.is_relative_to(source_directory):
            return resolved_path.relative_to(source_directory)

    return None


def _jvm_class_to_package_and_filename(class_str: str) -> Optional[Tuple[str, str]]:
    class_list = class_str.split(".")
    if len(class_list) < 1:
        return None
    package = ".".join(class_list[:-1])
    file_name = f"{class_list[-1]}.java"
    return (package, file_name)


def _parse_jvm_shell_output_line(
    line: str,
) -> Optional[Tuple[str, str, str, str, str, str]]:
    if not line.strip():
        return None
    parts = line.split(",", 5)

    if len(parts) != 6:
        return None

    caller_class_str = parts[0].strip()
    caller_method_str = parts[1].strip()
    callee_class_str = parts[2].strip()
    callee_method_str = parts[3].strip()
    _caller_file_name_from_log = parts[4].strip()
    caller_line_str = parts[5].strip()
    return (
        caller_class_str,
        caller_method_str,
        callee_class_str,
        callee_method_str,
        _caller_file_name_from_log,
        caller_line_str,
    )


def _resolve_jvm_path(
    class_str: str, path_map: list[Path], source_directory: Path
) -> Optional[Path]:
    class_resolve_result = _jvm_class_to_package_and_filename(class_str)
    if class_resolve_result:
        package, file_name_from_class = class_resolve_result
        return _package_to_path(
            path_map,
            source_directory,
            package,
            file_name_from_class,
        )
    return None


def _parse_call_trace_log_for_jvm_one_line(
    path_map: list[Path], source_directory: Path, line: str
) -> Optional[FunctionCall]:
    regex_match = re.match(JVM_FUNCTION_INVOKE_REGEX, line)

    if regex_match is None:
        return None

    caller_name = f"{regex_match.group(1)}.{regex_match.group(2)}"
    caller_line = int(regex_match.group(6))
    if caller_line == -1:
        return None

    callee_name = f"{regex_match.group(3)}.{regex_match.group(4)}"

    caller_path = _resolve_jvm_path(regex_match.group(1), path_map, source_directory)

    if caller_path is None:
        return None

    callee_path = _resolve_jvm_path(regex_match.group(3), path_map, source_directory)

    return FunctionCall(
        caller_file=caller_path,
        caller_name=caller_name,
        call_line=caller_line,
        callee_file=callee_path,
        callee_name=callee_name,
    )


def _simple_parse_from_shell_output_for_jvm(
    shell_output: str, source_directory: Path, path_map: list[Path]
) -> List[FunctionCall]:
    result: List[FunctionCall] = []
    lines = shell_output.strip().split("\n")
    for line in lines:
        parsed_parts = _parse_jvm_shell_output_line(line)
        if not parsed_parts:
            continue

        (
            caller_class_str,
            caller_method_str,
            callee_class_str,
            callee_method_str,
            _caller_file_name_from_log,
            caller_line_str,
        ) = parsed_parts

        try:
            caller_line = int(caller_line_str)
            if caller_line == -1:
                continue
        except ValueError:
            continue

        caller_name = f"{caller_class_str}.{caller_method_str}"
        callee_name = f"{callee_class_str}.{callee_method_str}"

        caller_path = _resolve_jvm_path(caller_class_str, path_map, source_directory)
        if caller_path is None:
            continue

        callee_path = _resolve_jvm_path(callee_class_str, path_map, source_directory)

        result.append(
            FunctionCall(
                caller_file=caller_path,
                caller_name=caller_name,
                call_line=caller_line,
                callee_file=callee_path,
                callee_name=callee_name,
            )
        )
    return result


def simple_parse_call_trace_log_for_jvm(
    log_content_for_hash: str,
    source_directory: Path,
    max_lines_for_saving: Optional[int],
    full_log_to_save: str,
    path_map: list[Path],
) -> List[FunctionCall]:
    log_hash = _generate_log_hash(log_content_for_hash)

    try:
        cache_sub_dir = DEFAULT_CACHE_DIRECTORY / "call_trace"
        cache_sub_dir.mkdir(parents=True, exist_ok=True)
        log_file_path = cache_sub_dir / f"{log_hash}.log"

        lines_to_save_list = full_log_to_save.split("\n")
        if (
            max_lines_for_saving is not None
            and len(lines_to_save_list) > max_lines_for_saving
        ):
            lines_to_save_list = lines_to_save_list[:max_lines_for_saving]

        with open(log_file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines_to_save_list))

    except Exception:
        return []

    filename_for_shell = log_file_path.as_posix()

    grep_invoke_cmd = f"grep -E '^\\[Invoke\\]' \"{filename_for_shell}\""
    sed_cmd = "sed -E -n 's/^\\[Invoke\\] caller class: ([^,]+), caller method: ([^,]+), callee class: ([^,]+), callee method: ([^,]+), file: ([^,]+), line: ([-+]?[0-9]+).*/\\1,\\2,\\3,\\4,\\5,\\6/p'"
    tac_cmd = "tac"
    awk_cmd = "awk '!seen[$0]++'"

    shell_command = f"{grep_invoke_cmd} | {sed_cmd} | {tac_cmd} | {awk_cmd} | {tac_cmd}"

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
        return _simple_parse_from_shell_output_for_jvm(
            shell_output, source_directory, path_map
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(
            f"Error during shell command execution in simple_parse_call_trace_log_for_jvm: {e}"
        )
        return []


def parse_call_trace_log_for_jvm(
    call_trace_log: str,
    source_directory: Path,
    simple: bool = False,
    max_lines: Optional[int] = None,
) -> List[FunctionCall]:
    path_map = _create_path_map(source_directory)

    if simple:
        return simple_parse_call_trace_log_for_jvm(
            log_content_for_hash=call_trace_log,
            source_directory=source_directory,
            max_lines_for_saving=max_lines,
            full_log_to_save=call_trace_log,
            path_map=path_map,
        )

    result: List[FunctionCall] = []
    lines = call_trace_log.split("\n")

    for line_content in lines:
        call_history = _parse_call_trace_log_for_jvm_one_line(
            path_map, source_directory, line_content.strip()
        )

        if call_history is not None:
            result.append(call_history)

    return result
