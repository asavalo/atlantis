import json
import logging
import os
import re
import shutil
from pathlib import Path
from typing import Dict, List, Optional, cast

from joblib import Memory
from python_aixcc_challenge.detection.models import AIxCCChallengeFullMode
from python_llm.api.actors import LlmApiManager
from python_oss_fuzz.path.functions import get_oss_fuzz_project_path
from python_oss_fuzz.path.globals import OSS_FUZZ_DIRECTORY, OSS_FUZZ_HELPER_FILE

from crete.atoms.detection import Detection
from crete.atoms.path import DEFAULT_CACHE_DIRECTORY
from crete.commons.interaction.functions import run_command
from crete.framework.environment.services.oss_fuzz import OssFuzzEnvironment
from crete.framework.environment_pool.services.mock import MockEnvironmentPool
from crete.framework.test_generator.contexts import TestGenerationContext
from crete.framework.test_generator.models import TestGenerationResult
from crete.framework.test_generator.services.constants import (
    CONTAINER_OUT_DIR,
    CONTAINER_SRC_DIR,
    DEV_TESTER_DIR,
    FILE_MAX_TOKEN,
    INFORMATION_DIR,
    MAJOR_PROJECT_NAMES,
    MAX_FILE_COUNT,
    MAX_SEARCH_DEPTH,
    STDERR_MAX_TOKEN,
    STDOUT_MAX_TOKEN,
    SUCCESS_DIR,
    SUCCESS_LOG_FILENAME,
    SUCCESS_TEST_FILENAME,
    TEST_DIR,
    TEST_RESULT_LOG_EXT,
    TEST_RESULT_LOG_PREFIX,
    TEST_SCRIPT_EXT,
    TEST_SCRIPT_PREFIX,
    TEST_TIMEOUT_MINUTES,
)
from crete.framework.test_generator.services.prompts import (
    FILE_EXTRACTOR_KEYWORDS,
    FILE_EXTRACTOR_PROMPTS,
    FILE_EXTRACTOR_SYSTEM_PROMPT,
    PromptType,
)
from crete.framework.test_generator.services.validator import LLMTestValidator

WORKDIR_REGEX = re.compile(r"\s*WORKDIR\s*([^\s]+)")


def shell_online(
    context: TestGenerationContext, project_name: str, command: str, timeout: int = 600
) -> tuple[str, str]:
    return run_command(
        command=(
            f"{OSS_FUZZ_HELPER_FILE} shell {project_name}",
            context["pool"].source_directory,
        ),
        timeout=timeout,
        input=f"{command}; exit $?".encode(),
        isatty=True,
    )


def container_path_from_host_absolute_path(
    context: TestGenerationContext, host_path: Path, detection: Detection
) -> Path:
    out_directory = context["pool"].out_directory
    return Path(CONTAINER_OUT_DIR) / host_path.relative_to(out_directory)


def host_path_from_container_absolute_path(
    context: TestGenerationContext, container_path: Path, detection: Detection
) -> Path:
    out_directory = context["pool"].out_directory
    return out_directory / container_path.relative_to(CONTAINER_OUT_DIR)


def _get_next_test_filename(test_dir: Path, prefix: str) -> Path:
    existing_tests = sorted(test_dir.glob(f"{prefix}_*{TEST_SCRIPT_EXT}"))
    return test_dir / f"{prefix}_{len(existing_tests)}{TEST_SCRIPT_EXT}"


def make_and_check_test_script(
    context: TestGenerationContext,
    detection: Detection,
    code: str,
    validator: LLMTestValidator,
) -> TestGenerationResult | None:
    test_script_path = make_script(context, detection, code, TEST_SCRIPT_PREFIX)
    return _check_test_script(context, detection, test_script_path, validator)


def make_script(
    context: TestGenerationContext, detection: Detection, code: str, prefix: str
) -> Path:
    out_directory = context["pool"].out_directory
    test_dir = out_directory / TEST_DIR
    test_dir.mkdir(parents=True, exist_ok=True)

    script_filename = _get_next_test_filename(test_dir, prefix)
    test_script_path = test_dir / script_filename
    test_script_path.write_text(code)
    test_script_path.chmod(0o755)
    return test_script_path


def _get_next_test_result_log_path(test_script_path: Path) -> Path:
    return test_script_path.with_name(
        test_script_path.name.replace(TEST_SCRIPT_EXT, TEST_RESULT_LOG_EXT).replace(
            f"{TEST_SCRIPT_PREFIX}_", f"{TEST_RESULT_LOG_PREFIX}_"
        )
    )


def get_success_script_path(
    context: TestGenerationContext, detection: Detection
) -> Path:
    out_directory = context["pool"].out_directory
    success_dir = out_directory / TEST_DIR / SUCCESS_DIR
    return success_dir / SUCCESS_TEST_FILENAME


def get_success_log_path(context: TestGenerationContext, detection: Detection) -> Path:
    out_directory = context["pool"].out_directory
    success_dir = out_directory / TEST_DIR / SUCCESS_DIR
    return success_dir / SUCCESS_LOG_FILENAME


def _copy_successful_test_to_success_dir(
    context: TestGenerationContext, test_script_path: Path, detection: Detection
) -> None:
    # Get success script and log paths
    success_script_path = get_success_script_path(context, detection)
    success_log_path = get_success_log_path(context, detection)

    # Create success directory only when copying successful test
    success_dir = success_script_path.parent
    success_dir.mkdir(parents=True, exist_ok=True)

    # Copy test script to success directory
    shutil.copy2(test_script_path, success_script_path)
    success_script_path.chmod(0o755)
    context["logger"].info(f"Successful test script copied to {success_script_path}")

    # Copy test result log to success directory if it exists
    test_result_log_path = _get_next_test_result_log_path(test_script_path)
    if test_result_log_path.exists():
        shutil.copy2(test_result_log_path, success_log_path)
        context["logger"].info(f"Test result log copied to {success_log_path}")


def truncate_with_token_constraint(
    output: str, max_token: int = STDOUT_MAX_TOKEN
) -> str:
    if len(output) <= max_token:
        return output

    summary_template = (
        "\n... (output truncated, showing first {} and last {} characters) ...\n"
    )
    summary_length = len(summary_template.format("0000", "0000"))

    # Reserve a small buffer (10 characters) to account for potential calculation errors
    available_content_length = max_token - summary_length - 10
    half_length = available_content_length // 2

    start_output = output[:half_length]
    end_output = output[-half_length:]
    summary_message = summary_template.format(len(start_output), len(end_output))
    result = f"{start_output}{summary_message}{end_output}"

    # If the result is still too long, trim it further
    if len(result) > max_token:
        excess = len(result) - max_token
        # Trim evenly from both start and end outputs
        trim_each = (excess // 2) + 1  # Add 1 to ensure we trim enough
        start_output = start_output[:-trim_each]
        end_output = end_output[trim_each:]
        summary_message = summary_template.format(len(start_output), len(end_output))
        result = f"{start_output}{summary_message}{end_output}"

    # Verify the final length is within the limit
    assert len(result) <= max_token, (
        f"Truncated output length {len(result)} exceeds max_token {max_token}"
    )

    return result


def find_file_in_system(
    context: TestGenerationContext,
    detection: Detection,
    filename: str,
    max_results: int = 10,
) -> str:
    files = find_files(
        context,
        detection,
        filename,
        base_dir="/",
        max_depth=MAX_SEARCH_DEPTH,
        use_iname=False,
        add_wildcards=False,
    )

    files = files[:max_results]

    if not files:
        return f"There is no file named '{filename}' in the system"

    return "\n".join(files)


def extract_missing_files_from_output(
    context: TestGenerationContext,
    detection: Detection,
    stdout: str,
    stderr: str,
    max_files: int = 10,
    llm_api_manager: Optional[LlmApiManager] = None,
) -> tuple[List[str], str]:
    missing_files: List[str] = []
    extra_info = ""

    # Combine stdout and stderr for analysis
    combined_output = f"{stdout}\n\n{stderr}"

    # Define error keywords
    keywords = [
        "No such file",
        "not found",
        "cannot",
        "failed to run",
        "timeout:",
        "Errno 2",
        "can't open file",
        "Permission denied",
    ]

    # Extract lines containing error keywords
    error_lines: List[str] = []
    for line in combined_output.split("\n"):
        if any(keyword in line for keyword in keywords):
            error_lines.append(line)

    # Human-based regex parsing using extract_file_by_human with "missing_file" prompt type
    # Only pass the error lines to extract_file_by_human
    error_content = "\n".join(error_lines)
    human_missing_file_names = extract_file_by_human(
        context,
        detection,
        error_content,
        cast(PromptType, "missing_file"),  # Cast string to PromptType
    )

    # LLM-based extraction
    llm_missing_file_names: List[str] = []
    if llm_api_manager:
        # Use extract_file_by_llm with "missing_file" prompt type
        llm_missing_file_names = extract_file_by_llm(
            context,
            detection,
            llm_api_manager,
            combined_output,  # LLM gets the full output for better context
            cast(PromptType, "missing_file"),  # Cast string to PromptType
        )

    # Combine and limit the file names
    missing_file_names = list(set(human_missing_file_names + llm_missing_file_names))[
        :max_files
    ]
    missing_files = missing_file_names  # Store file names directly

    if missing_file_names:
        extra_info = "[missing_files]\n"
        for file_name in missing_file_names:
            files = find_files(
                context,
                detection,
                file_name,
                base_dir="/",
                max_depth=5,
                use_iname=False,
                add_wildcards=False,
            )
            max_files = 3
            if len(files) > max_files:
                files.sort(key=lambda path: path.count("/"))
                files = files[:max_files]

            if len(files) == 0:
                extra_info += (
                    f"\n--- {file_name} ---\nCould not find file in the system\n"
                )
            else:
                extra_info += f"\n--- {file_name} ---\n{'\n'.join(files)}\n"

    return missing_files, extra_info


def extract_log_files_from_output(
    context: TestGenerationContext,
    detection: Detection,
    stdout: str,
    stderr: str,
    max_files: int = 5,
) -> str:
    # Simply extract file paths with .log extension
    log_files_set: set[str] = set()

    # Extract log file paths from stdout and stderr
    for line in stdout.split("\n") + stderr.split("\n"):
        if ".log" in line:
            # Split by whitespace and find words containing .log
            for word in line.split():
                if ".log" in word:
                    # Remove quotes and other characters
                    clean_word = word.strip("'\",:;()[]{}").strip()
                    if clean_word.endswith(".log"):
                        log_files_set.add(clean_word)

    log_files = list(log_files_set)

    # Read log file contents
    extra_info = "[log_files]\n" if len(log_files) >= 1 else ""

    for log_file in log_files[:max_files]:
        log_content = ""

        files = find_files(
            context,
            detection,
            os.path.basename(log_file),
            base_dir="/",
            max_depth=MAX_SEARCH_DEPTH,
            use_iname=True,
            add_wildcards=False,
        )

        for file_path in files:
            try:
                log_content = read_file_content(context, detection, file_path)
                if log_content:
                    break
            except Exception as e:
                context["logger"].warning(
                    f"Failed to read container file {file_path}: {e}"
                )

        # Add log content to extra info
        if log_content != "":
            log_content = truncate_with_token_constraint(log_content, FILE_MAX_TOKEN)
            extra_info += f"\n--- {log_file} ---\n{log_content}\n"
        else:
            extra_info += f"\n--- {log_file} ---\nCould not read log file content\n"

    return extra_info


def _check_test_script(
    context: TestGenerationContext,
    detection: Detection,
    test_script_path: Path,
    validator: LLMTestValidator,
) -> TestGenerationResult:
    container_test_script_path = container_path_from_host_absolute_path(
        context, test_script_path, detection
    )
    try:
        result_stdout, result_stderr = context["environment"].shell(
            context,
            f"export TERM=dumb PY_COLORS=0 NO_COLOR=1 CLICOLOR=0 CLICOLOR_FORCE=0 && chmod +x {container_test_script_path} && timeout {TEST_TIMEOUT_MINUTES}m {container_test_script_path}; echo $?",
        )
        result_stdout = truncate_with_token_constraint(result_stdout, STDOUT_MAX_TOKEN)
        result_stderr = truncate_with_token_constraint(result_stderr, STDERR_MAX_TOKEN)

    except Exception as e:
        context["logger"].exception("Failed to run test script")
        log_path = _get_next_test_result_log_path(test_script_path)
        log_content = "[error]\n" + str(e)
        log_path.write_text(log_content, encoding="utf-8")
        context["logger"].info(f"Test result log saved to {log_path}")

        return TestGenerationResult(
            status="failure",
            output=str(e),
            path=test_script_path,
        )

    log_path = _get_next_test_result_log_path(test_script_path)
    log_content = "[stdout]\n" + result_stdout

    combined_output = f"[stdout]\n{result_stdout}\n\n"

    # Extract missing files information using LLM
    _, missing_files_info = extract_missing_files_from_output(
        context,
        detection,
        result_stdout,
        result_stderr,
        llm_api_manager=validator.llm_api_manager,
    )

    if missing_files_info:
        log_content += "\n" + missing_files_info
        combined_output += f"\n{missing_files_info}\n"

    # Extract log files information
    log_files_info = extract_log_files_from_output(
        context, detection, result_stdout, result_stderr
    )

    if log_files_info:
        log_content += "\n" + log_files_info
        combined_output += f"\n[missing_logging_info]\n{log_files_info}\n"

    log_path.write_text(log_content, encoding="utf-8")
    context["logger"].info(f"Test result log saved to {log_path}")

    # Pass the combined output including log file contents to the validator
    validation_result = validator.validate(context, combined_output)

    if validation_result:
        status = "success" if validation_result["test_success"] else "failure"
        validation_info = f"[validation]\n{json.dumps(validation_result, indent=2)}"
        log_content += "\n" + validation_info
        combined_output += f"\n{validation_info}\n"
        log_path.write_text(log_content, encoding="utf-8")

        if status == "success":
            _copy_successful_test_to_success_dir(context, test_script_path, detection)

        return TestGenerationResult(
            status=status,
            output=combined_output,
            path=test_script_path,
        )

    matches = re.search(r"exit\s*[\r\n]*\s*$", result_stdout, re.IGNORECASE)
    status = "success" if matches else "failure"

    if status == "success":
        _copy_successful_test_to_success_dir(context, test_script_path, detection)

    return TestGenerationResult(
        status=status,
        output=combined_output,
        path=test_script_path,
    )


def find_files(
    context: TestGenerationContext,
    detection: Detection,
    target: str,
    base_dir: str = CONTAINER_SRC_DIR,
    max_depth: int = MAX_SEARCH_DEPTH,
    use_iname: bool = True,
    add_wildcards: bool = False,
) -> List[str]:
    """
    Find files in the system with flexible search options.

    Args:
        context: The test generation context
        detection: The detection object
        target: The target file or pattern to search for
        base_dir: The base directory to start the search from (default: CONTAINER_SRC_DIR)
        max_depth: Maximum depth for the search (default: MAX_SEARCH_DEPTH)
        use_iname: Whether to use case-insensitive search (default: True)
        add_wildcards: Whether to add wildcards around the target (default: False)

    Returns:
        A list of file paths matching the search criteria
    """
    search_target = f"*{target}*" if add_wildcards else target
    name_option = "-iname" if use_iname else "-name"
    command = f"export TERM=dumb PY_COLORS=0 NO_COLOR=1 CLICOLOR=0 CLICOLOR_FORCE=0 && find {base_dir} -maxdepth {max_depth} -type f {name_option} '{search_target}'"

    try:
        stdout, _ = context["environment"].shell(context, command)
        return [
            line.strip()
            for line in stdout.strip().split("\n")
            if line.strip() and line.startswith(base_dir)
        ]
    except Exception as e:
        context["logger"].warning(f"Failed to find files: {e}")
        return []


# Legacy functions that use the new unified function
def find_files_in_depth(
    context: TestGenerationContext,
    detection: Detection,
    target: str,
    max_depth: int = MAX_SEARCH_DEPTH,
) -> List[str]:
    """Legacy function that uses find_files with wildcards"""
    return find_files(
        context, detection, target, max_depth=max_depth, add_wildcards=True
    )


def find_exact_files_in_depth(
    context: TestGenerationContext,
    detection: Detection,
    target_file: str,
    max_depth: int = MAX_SEARCH_DEPTH,
) -> List[str]:
    """Legacy function that uses find_files without wildcards"""
    return find_files(context, detection, target_file, max_depth=max_depth)


def read_file_content(
    context: TestGenerationContext, detection: Detection, file_path: str
) -> str:
    try:
        file = host_path_from_container_absolute_path(
            context, Path(file_path), detection
        )
        return file.read_text(encoding="utf-8")
    except Exception as e:
        context["logger"].warning(f"Failed to read container file {file_path}: {e}")
        return ""


def extract_file_by_human(
    context: TestGenerationContext,
    detection: Detection,
    content: str,
    prompt_type: PromptType,
) -> List[str]:
    if prompt_type not in FILE_EXTRACTOR_KEYWORDS:
        return []

    keywords = FILE_EXTRACTOR_KEYWORDS[prompt_type]
    file_names: List[str] = []

    # Extract file names containing keywords from content
    for keyword in keywords:
        pattern = r"[a-zA-Z0-9_\-\.]*" + re.escape(keyword).lower()
        matches = re.finditer(pattern, content.lower(), re.IGNORECASE)
        for match in matches:
            original_file_name = content[match.start() : match.end()]
            # Only return file names, not file paths
            file_names.append(original_file_name)

    # Remove duplicates
    return list(set(file_names))


def extract_file_by_llm(
    context: TestGenerationContext,
    detection: Detection,
    llm_api_manager: LlmApiManager,
    content: str,
    prompt_type: PromptType,
) -> List[str]:
    if prompt_type not in FILE_EXTRACTOR_PROMPTS:
        context["logger"].warning(f"Unknown prompt type: {prompt_type}")
        return []

    try:
        chat_model = llm_api_manager.langchain_litellm()
        truncated_content = truncate_with_token_constraint(content, STDOUT_MAX_TOKEN)
        response = chat_model.invoke(
            [
                {"role": "system", "content": FILE_EXTRACTOR_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": FILE_EXTRACTOR_PROMPTS[prompt_type].format(
                        content=truncated_content
                    ),
                },
            ]
        )

        response_content = cast(str, response.content)  # pyright: ignore
        file_names = [
            line.strip() for line in response_content.split("\n") if line.strip()
        ]

        # Only return file names without searching for file paths
        return file_names

    except Exception as e:
        context["logger"].warning(f"Failed to extract files using LLM: {e}")
        return []


def extract_file_info(
    context: TestGenerationContext,
    detection: Detection,
    target: str,
    file_name: str,
    key: str,
    information_dir: Path | None = None,
) -> Dict[str, str]:
    if information_dir is None:
        out_directory = context["pool"].out_directory
        information_dir = out_directory / TEST_DIR / INFORMATION_DIR
        information_dir.mkdir(parents=True, exist_ok=True)

    output_file_path = information_dir / file_name

    if output_file_path.exists():
        context["logger"].info(
            f"{file_name} already exists at {output_file_path}. Skipping extraction."
        )
        return {key: output_file_path.read_text(encoding="utf-8")}

    files = find_files(context, detection, target, add_wildcards=True)

    content = ""
    file_count = 0
    for file_path in files:
        if file_count >= MAX_FILE_COUNT:
            break
        file_content = read_file_content(context, detection, file_path)
        if file_content:
            file_content = truncate_with_token_constraint(file_content, FILE_MAX_TOKEN)
            content += f"\n=== File: {file_path} ===\n{file_content}\n"
            file_count += 1

    output_file_path.write_text(content, encoding="utf-8")
    return {key: content}


def workdir_from_lines(lines: List[str], default: str = "/src") -> str:
    """Gets the WORKDIR from the given lines."""
    for line in reversed(lines):  # reversed to get last WORKDIR.
        match = re.match(WORKDIR_REGEX, line)
        if match:
            workdir = match.group(1)
            workdir = workdir.replace("$SRC", "/src")

            if not os.path.isabs(workdir):
                workdir = os.path.join("/src", workdir)

            return os.path.normpath(workdir)

    return default


def _workdir_from_dockerfile(project_name: str) -> str:
    """Parses WORKDIR from the Dockerfile for the given project."""
    dockerfile_path = get_oss_fuzz_project_path(project_name) / "Dockerfile"
    try:
        with open(dockerfile_path, "r") as file_handle:
            lines = file_handle.readlines()
        return workdir_from_lines(lines, default=os.path.join("/src", project_name))
    except Exception as e:
        logging.warning(
            f"Failed to parse WORKDIR from Dockerfile for {project_name}: {e}"
        )
        return os.path.join("/src", project_name)


def make_oss_context(
    project_name: str,
) -> tuple[TestGenerationContext, Detection]:
    try:
        oss_project_output_directory = (
            OSS_FUZZ_DIRECTORY / "build/out" / project_name / "src"
        )
        oss_project_cache_directory = (
            DEFAULT_CACHE_DIRECTORY / "oss-fuzz" / project_name
        )

        environment_context = cast(
            TestGenerationContext,
            {
                "logger": logging.getLogger(f"build_project_{project_name}"),
                "logging_prefix": f"build_project_{project_name}",
                "memory": Memory(verbose=0),
            },
        )

        detection = Detection(
            mode=AIxCCChallengeFullMode(type="full", base_ref="HEAD"),
            project_name=project_name,
            language="c",
            blobs=[],
            vulnerability_identifier="",
        )

        toml_dir = DEFAULT_CACHE_DIRECTORY / "oss-fuzz-toml"
        toml_dir.mkdir(parents=True, exist_ok=True)
        detection_toml_path = toml_dir / f"{project_name}.toml"
        detection_toml_path.write_text(f'[project]\nname = "{project_name}"\n')

        pool = MockEnvironmentPool(
            challenge_project_directory=oss_project_cache_directory,
            detection_toml_file=detection_toml_path,
        )

        # Explicitly set output directory
        pool.out_directory = oss_project_output_directory.parent

        environment = OssFuzzEnvironment(
            pool=pool,
            project_name=project_name,
            checkout_ref="HEAD",
            max_timeout=20 * 60,
        )

        environment_context["environment"] = environment  # type: ignore
        environment_context["pool"] = pool
        environment_context["detection"] = detection  # type: ignore

        return environment_context, detection
    except Exception as e:
        logging.error(f"Context creation failed: {str(e)}")
        raise ValueError(f"Failed to create context for {project_name}: {str(e)}")


def make_usermode(context: TestGenerationContext) -> bool:
    """Set proper permissions so files can be deleted without sudo.

    Args:
        context: The test generation context

    Returns:
        bool: True if permissions were set successfully, False otherwise
    """
    try:
        # Get output directory
        out_directory = context["pool"].out_directory

        # First, try to set permissions in the container
        context["environment"].shell(
            context,
            (
                f"chmod -R 777 /work && chmod -R 777 /out && chmod -R 777 /src && "
                f"chown -R {os.getuid()}:{os.getgid()} /work && "
                f"chown -R {os.getuid()}:{os.getgid()} /out && "
                f"chown -R {os.getuid()}:{os.getgid()} /src"
            ),
        )
        logging.info(
            "Applied permissions to container files to allow deletion without sudo"
        )

        # Also try to fix host file permissions for output directory
        try:
            if out_directory.exists():
                os.system(f"chmod -R 777 {out_directory}")
                logging.info(f"Applied permissions to host directory: {out_directory}")
        except Exception as host_error:
            logging.warning(
                f"Could not set permissions on host directory: {host_error}"
            )

        return True
    except Exception as perm_error:
        logging.warning(f"Failed to set permissions: {perm_error}")
        return False


def reset_usermode(context: TestGenerationContext) -> bool:
    """Reset permissions to default.

    Args:
        context: The test generation context

    Returns:
        bool: True if permissions were reset successfully, False otherwise
    """
    try:
        # Don't try to reset permissions inside the container, as this can cause issues
        # Instead, focus on making sure host files are accessible

        # Get output directory
        out_directory = context["pool"].out_directory

        # Try to fix host file permissions to be more standard
        try:
            if out_directory.exists():
                # Set more reasonable permissions (read-write for user, read for group/others)
                os.system(f"chmod -R 755 {out_directory}")
                logging.info(f"Reset host directory permissions: {out_directory}")
        except Exception as host_error:
            logging.warning(
                f"Could not reset permissions on host directory: {host_error}"
            )

        return True
    except Exception as perm_error:
        logging.warning(f"Failed to reset permissions: {perm_error}")
        return False


def build_oss_project(context: TestGenerationContext, detection: Detection) -> bool:
    try:
        project_name = detection.project_name
        oss_project_output_directory = (
            OSS_FUZZ_DIRECTORY / "build/out" / project_name / "src"
        )
        oss_project_cache_directory = (
            DEFAULT_CACHE_DIRECTORY / "oss-fuzz" / project_name
        )

        cache = os.path.exists(oss_project_cache_directory)

        if not cache:
            os.makedirs(oss_project_cache_directory, exist_ok=True)
            os.makedirs(
                DEFAULT_CACHE_DIRECTORY / "oss-fuzz-src" / project_name, exist_ok=True
            )

            workdir = _workdir_from_dockerfile(project_name)
            logging.info(f"Using WORKDIR from Dockerfile: {workdir}")

            shell_online(context, project_name, f"cp -r {workdir} /out/src")

            shutil.copytree(
                oss_project_output_directory,
                DEFAULT_CACHE_DIRECTORY / "oss-fuzz-src" / project_name,
                dirs_exist_ok=True,
            )
            shutil.copytree(
                oss_project_output_directory,
                oss_project_cache_directory,
                dirs_exist_ok=True,
            )
            context["environment"].build(context)
            shutil.copytree(
                DEFAULT_CACHE_DIRECTORY / "oss-fuzz-src" / project_name,
                oss_project_output_directory,
                dirs_exist_ok=True,
            )

        return True
    except Exception as e:
        logging.error(f"Build failed: {str(e)}")
        return False


def clean_oss_project_docker(
    context: TestGenerationContext, detection: Detection
) -> str:
    project_name = detection.project_name
    logger = logging.getLogger("clean_project")

    docker_image = f"gcr.io/oss-fuzz/{project_name}"
    try:
        cmd = f"docker rmi -f {docker_image}"
        run_command((cmd, Path(".")))
        logger.info(f"Removed Docker image: {docker_image}")
    except Exception as e:
        logger.warning(f"Failed to remove Docker image '{docker_image}': {e}")

    return f"Cleaned: {project_name}"


def clean_test_generator(context: TestGenerationContext, detection: Detection) -> None:
    project_name = detection.project_name
    out_directory = context["pool"].out_directory
    test_dir = out_directory / TEST_DIR

    if not test_dir.exists():
        logging.info(f"Test directory {test_dir} does not exist, nothing to clean")
        return

    logging.info(f"Cleaning test generator files for project: {project_name}")

    # Delete only generated test scripts and log files
    for file_path in test_dir.iterdir():
        if file_path.is_file() and (
            file_path.name.startswith(TEST_SCRIPT_PREFIX)
            or file_path.name.startswith("test_result_log")
        ):
            try:
                file_path.unlink()
                logging.info(f"Deleted: {file_path}")
            except Exception as e:
                logging.warning(f"Failed to delete {file_path}: {e}")

    logging.info(f"Finished cleaning test generator files for project: {project_name}")


def clean_project_completely(
    context: TestGenerationContext, detection: Detection
) -> None:
    """Clean all project files including build directories and cache.

    This function attempts to remove all files related to a project, but
    will continue even if some files cannot be removed due to permission issues.

    Args:
        context: The test generation context
        detection: The detection object containing project information
    """
    project_name = detection.project_name
    out_directory = context["pool"].out_directory

    # Set proper permissions before attempting to delete files
    try:
        make_usermode(context)
        logging.info("Set user permissions before cleaning project files")
    except Exception as e:
        logging.warning(
            f"Failed to set user permissions: {e}, will attempt cleanup anyway"
        )

    # First try to fix permissions on out_directory to enable deletion
    try:
        if out_directory.exists():
            os.system(f"chmod -R 777 {out_directory}")
    except Exception:
        # Just continue if this fails
        pass

    # Clean build/out directory
    if out_directory.exists():
        logging.info(f"Deleting build directory: {out_directory}")
        try:
            # Try to delete recursively
            shutil.rmtree(out_directory)
            logging.info(f"Successfully deleted {out_directory}")
        except PermissionError:
            logging.warning(
                f"Permission error when deleting {out_directory}, skipping..."
            )
            # Try to use system commands as a fallback
            try:
                os.system(f"rm -rf {out_directory}")
                if not out_directory.exists():
                    logging.info(
                        f"Successfully deleted {out_directory} using system command"
                    )
            except Exception:
                pass
        except Exception as e:
            logging.error(f"Failed to delete {out_directory}: {e}")

    # Clean build/work directory with similar approach
    work_dir = OSS_FUZZ_DIRECTORY / "build/work" / project_name
    if work_dir.exists():
        logging.info(f"Deleting work directory: {work_dir}")
        try:
            # Try to delete recursively
            shutil.rmtree(work_dir)
            logging.info(f"Successfully deleted {work_dir}")
        except PermissionError:
            logging.warning(f"Permission error when deleting {work_dir}, skipping...")
            # Try to use system commands as a fallback
            try:
                os.system(f"rm -rf {work_dir}")
                if not work_dir.exists():
                    logging.info(
                        f"Successfully deleted {work_dir} using system command"
                    )
            except Exception:
                pass
        except Exception as e:
            logging.error(f"Failed to delete {work_dir}: {e}")

    # Clean cache directories with similar approach
    cache_dirs = [
        DEFAULT_CACHE_DIRECTORY / "oss-fuzz" / project_name,
        DEFAULT_CACHE_DIRECTORY / "oss-fuzz-src" / project_name,
    ]

    for cache_dir in cache_dirs:
        if cache_dir.exists():
            logging.info(f"Deleting cache directory: {cache_dir}")
            try:
                # Try to delete recursively
                shutil.rmtree(cache_dir)
                logging.info(f"Successfully deleted {cache_dir}")
            except PermissionError:
                logging.warning(
                    f"Permission error when deleting {cache_dir}, skipping..."
                )
                # Try to use system commands as a fallback
                try:
                    os.system(f"rm -rf {cache_dir}")
                    if not cache_dir.exists():
                        logging.info(
                            f"Successfully deleted {cache_dir} using system command"
                        )
                except Exception:
                    pass
            except Exception as e:
                logging.error(f"Failed to delete {cache_dir}: {e}")

    logging.info(
        f"Completed cleaning project: {project_name} (some directories may remain if permission issues occurred)"
    )


def clean_dev_tester(context: TestGenerationContext, detection: Detection) -> None:
    project_name = detection.project_name
    out_directory = context["pool"].out_directory

    # Path to the dev_tester directory
    dev_tester_dir = out_directory / TEST_DIR / DEV_TESTER_DIR

    # Remove the directory if it exists
    if dev_tester_dir.exists():
        print(
            f"Cleaning dev_tester directory for project {project_name}: {dev_tester_dir}"
        )
        try:
            shutil.rmtree(dev_tester_dir)
            print(
                f"Successfully cleaned dev_tester directory for project {project_name}"
            )
        except PermissionError:
            print(f"Permission error when deleting {dev_tester_dir}, skipping...")
        except Exception as e:
            print(f"Error cleaning dev_tester directory: {e}")


def get_all_oss_projects() -> List[str]:
    """Get all OSS-Fuzz project names using a fallback method.
    We'll try to get the list from different sources and return all major projects if all fails.

    Returns:
        List of OSS-Fuzz project names
    """
    try:
        # Try to import from the python_aixcc_challenge package first
        try:
            # Import the module directly and use 'getattr' to avoid import errors
            import python_aixcc_challenge.project.functions as aixcc_functions

            # Call the function through getattr to avoid direct import issues
            get_projects_func = getattr(aixcc_functions, "get_all_oss_project_names")
            return get_projects_func()  # type: ignore
        except (ImportError, AttributeError):
            pass

        # Get project list from OSS_FUZZ_DIRECTORY/projects
        projects_dir = Path(OSS_FUZZ_DIRECTORY) / "projects"
        if projects_dir.exists() and projects_dir.is_dir():
            projects = [p.name for p in projects_dir.iterdir() if p.is_dir()]
            if projects:
                logging.info(f"Found {len(projects)} projects in OSS_FUZZ_DIRECTORY")
                return projects

        # Fallback to MAJOR_PROJECT_NAMES as a last resort
        logging.warning(
            "Could not get all OSS-Fuzz projects, using major projects list"
        )
        return MAJOR_PROJECT_NAMES
    except Exception as e:
        logging.error(f"Error getting all OSS project names: {e}")
        return MAJOR_PROJECT_NAMES


def get_project_names(mode: str, projects: Optional[str] = None) -> List[str]:
    """Get project names based on the benchmark mode

    Args:
        mode: 'small' for major projects only, 'big' for all OSS-Fuzz projects
        projects: Optional comma-separated list of specific projects to test

    Returns:
        List of project names to benchmark
    """
    if projects:
        # If specific projects are provided, use those regardless of mode
        return [p.strip() for p in projects.split(",")]

    if mode == "small":
        # Small mode: use only the major projects
        return MAJOR_PROJECT_NAMES
    else:
        # Big mode: use all OSS-Fuzz projects
        return get_all_oss_projects()
