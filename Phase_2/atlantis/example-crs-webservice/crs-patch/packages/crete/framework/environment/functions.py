import subprocess
from pathlib import Path
from typing import List, Set

from python_aixcc_challenge.language.types import Language
from python_crs_architecture import CRS_IDENTIFIER_BINARY
from unidiff import PatchSet, UnidiffParseError

from crete.atoms.detection import Detection
from crete.commons.interaction.exceptions import CommandInteractionError
from crete.commons.interaction.functions import run_command
from crete.commons.logging.context_managers import logging_performance
from crete.commons.logging.hooks import use_logger
from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment.exceptions import (
    ChallengePoVFoundError,
    ChallengeWrongPatchError,
)
from crete.framework.environment.protocols import EnvironmentProtocol

_logger = use_logger("environment")


def rsync_directory(source_directory: Path, target_directory: Path):
    if not target_directory.parent.exists():
        target_directory.parent.mkdir(parents=True)

    try:
        subprocess.check_call(
            ["rsync", "-a", "--delete", f"{source_directory}/", str(target_directory)]
        )
    except subprocess.CalledProcessError as e:
        if e.returncode == 24:
            # NOTE: I don't know why but rsync returns 24 if some files vanished during the transfer.
            #       This is not a fatal error, so we just ignore it.
            pass
        else:
            raise e


def resolve_project_path(
    file: Path, source_directory: Path, only_file: bool = True
) -> Path | None:
    """
    Resolves a file path relative to the source directory.

    Handles two cases:
    1. Direct path resolution against source directory
    2. Recursive search for matching file path pattern

    Args:
        file: Path to resolve
        source_directory: Base directory to resolve against

    Returns:
        Resolved Path if found, None otherwise
    """
    # Try direct path resolution first
    for sub_path in _get_relative_sub_paths(file):
        resolved_path = (source_directory / sub_path).resolve()
        if resolved_path.exists() and (resolved_path.is_file() if only_file else True):
            return resolved_path

    # Fall back to recursive pattern matching
    for sub_path in _get_relative_sub_paths(file):
        if resolved_path := _find_sub_path_matching_file(
            source_directory, sub_path, only_file
        ):
            return resolved_path

    return None


def _get_relative_sub_paths(path: Path) -> list[Path]:
    """Helper to get all possible relative sub-paths"""
    return [
        Path(*path.parts[i:])
        for i in range(len(path.parts))
        if not Path(*path.parts[i:]).is_absolute()
    ]


def _find_sub_path_matching_file(
    source_directory: Path, sub_path: Path, only_file: bool = True
) -> Path | None:
    """
    Find a file in the source directory that matches the given sub_path.

    Example:
        source_directory = /path/to/source
        sub_path = com/aixcc/mock_java/App.java
        Returns: /path/to/source/src/main/java/com/aixcc/mock_java/App.java
    """
    if sub_path.is_absolute():
        return None

    source_directory = source_directory.resolve()

    for path in source_directory.rglob(sub_path.name):
        if (
            path.is_file()
            and path.as_posix().endswith(sub_path.as_posix())
            and (not only_file or path.is_file())
        ):
            return path

    return None


def environment_as_command_line_arguments(env: dict[str, str]) -> str:
    return " ".join(f'-e {k}="{v}"' for k, v in env.items())


def get_pov_results(
    environment: EnvironmentProtocol, context: EnvironmentContext, detection: Detection
) -> tuple[bytes, bytes] | None:
    try:
        with logging_performance(context, "Running a pov"):
            environment.run_pov(context, detection)
        return None
    except AssertionError:
        return None
    except ChallengePoVFoundError as e:
        return e.stdout, e.stderr


def check_valid_diff(diff: str, source_directory: Path, language: Language) -> bool:
    """
    Validates a diff by checking if it:
    1. Has a valid diff format
    2. Only modifies existing files
    3. Does not modify fuzzer files (either by name or content)

    Args:
        diff: The diff string to validate
        source_directory: The root directory of the source code

    Returns:
        bool: True if the diff is valid

    Raises:
        ChallengeWrongPatchError: If the diff is invalid for any reason
    """
    try:
        file_paths = _extract_file_paths_from_diff(diff)
    except UnidiffParseError as e:
        _logger.warning(f"Unidiff parse error: {e}")
        return True

    for file_path in file_paths:
        file_path = source_directory / file_path
        if not (file_path).exists():
            _logger.warning(f"File {file_path} does not exist")
            return True

        if _has_fuzz_file_path(file_path):
            _logger.warning(f"{file_path} is a harness file")
            raise ChallengeWrongPatchError(
                stdout=b"",
                stderr=f"Permission denied: '{file_path}' cannot be modified because it is a harness file".encode(),
            )

        if _has_llvm_fuzzer_method(file_path):
            _logger.warning(f"{file_path} is a harness file")
            raise ChallengeWrongPatchError(
                stdout=b"",
                stderr=f"Permission denied: '{file_path}' cannot be modified because it is a harness file".encode(),
            )

        try:
            is_valid_language = check_valid_language(file_path, language)
        except Exception as e:
            _logger.warning(
                f"Unknown error while checking language validity: {file_path}, {e}"
            )
            is_valid_language = True

        if not is_valid_language:
            _logger.warning(f"{file_path} is not a valid language file")
            raise ChallengeWrongPatchError(
                stdout=b"",
                stderr=f"Permission denied: '{file_path}' cannot be modified because it is not a valid language file".encode(),
            )

    return True


def _has_llvm_fuzzer_method(file_path: Path) -> bool:
    content = file_path.read_text(errors="replace")
    fuzzer_methods = [
        "LLVMFuzzerTestOneInput",
        "LLVMFuzzerInitialize",
        "fuzzerTestOneInput",
        "fuzzerInitialize",
    ]

    if any(method in content for method in fuzzer_methods):
        return True

    return False


def _has_fuzz_file_path(file_path: Path) -> bool:
    fuzz_file_names = ["fuzz", "harness", "Fuzzer"]

    if any(name in file_path.name for name in fuzz_file_names):
        return True

    return False


def _extract_file_paths_from_diff(diff: str) -> List[Path]:
    patch_set = PatchSet.from_string(diff)
    diff_files: Set[Path] = set()

    for patched_file in patch_set:
        # Get the file path - unidiff provides clean path handling
        old_file_path = patched_file.source_file
        new_file_path = patched_file.target_file

        if old_file_path and old_file_path != "/dev/null":
            diff_files.add(Path(old_file_path.removeprefix("a/")))

        if new_file_path and new_file_path != "/dev/null":
            diff_files.add(Path(new_file_path.removeprefix("b/")))

    return list(diff_files)


def check_valid_language(file_path: Path, language: Language) -> bool:
    if not CRS_IDENTIFIER_BINARY.exists():
        _logger.warning(f"Identifier binary not found: {CRS_IDENTIFIER_BINARY}")
        raise FileNotFoundError(f"Identifier binary not found: {CRS_IDENTIFIER_BINARY}")

    if language in ["c", "c++", "cpp"]:
        language_type = "c"
    elif language == "jvm":
        language_type = "java"
    else:
        _logger.warning(f"Unsupported language: {language}")
        raise ValueError(f"Unsupported language: {language}")

    try:
        run_command(
            (
                f"{CRS_IDENTIFIER_BINARY} --language {language_type} --path {file_path}",
                Path("."),
            )
        )
    except CommandInteractionError as e:
        if e.return_code == 1:
            return False
        else:
            _logger.warning(
                f"Identifier binary failed: return code {e.return_code}, stderr {e.stderr}, stdout {e.stdout}"
            )

    return True
