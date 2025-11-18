import re
import shutil
from pathlib import Path
from typing import Any, TypeVar

from crete.atoms.action import HeadAction
from crete.atoms.detection import Detection
from crete.atoms.path import PACKAGES_DIRECTORY
from crete.framework.agent.contexts import AgentContext
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.fault_localizer.contexts import FaultLocalizationContext
from crete.framework.insighter.contexts import InsighterContext


def mock_fault_localization_context(context: AgentContext) -> FaultLocalizationContext:
    return FaultLocalizationContext(
        memory=context["memory"],
        pool=context["pool"],
        crash_log_analyzer=context["crash_log_analyzer"],
        call_trace_snapshot=context["call_trace_snapshot"],
        logger=context["logger"],
        logging_prefix=context["logging_prefix"],
        language_parser=context["language_parser"],
        lsp_client=context["lsp_client"],
        sanitizer_name=context["sanitizer_name"],
    )


def mock_insighter_context(context: AgentContext) -> InsighterContext:
    return InsighterContext(
        memory=context["memory"],
        pool=context["pool"],
        crash_log_analyzer=context["crash_log_analyzer"],
        call_trace_snapshot=context["call_trace_snapshot"],
        logger=context["logger"],
        logging_prefix=context["logging_prefix"],
        language_parser=context["language_parser"],
        lsp_client=context["lsp_client"],
        sanitizer_name=context["sanitizer_name"],
    )


def copy_directory(
    source_directory: Path, target_directory: Path, overwrite: bool = False
) -> bool:
    if target_directory.exists() and not overwrite:
        return False

    shutil.rmtree(target_directory, ignore_errors=True)
    shutil.copytree(source_directory, target_directory)
    return True


def move_file(source_file: Path, target_file: Path) -> bool:
    if target_file.exists():
        return False

    shutil.move(source_file, target_file)
    return True


T = TypeVar("T", str, bytes)


def compare_portable_text(expected: T, actual: T) -> bool:
    def remove_spaces(text: T) -> T:
        match text:
            case str():
                return re.sub(r"\s+", " ", text)
            case bytes():
                return re.sub(rb"\s+", b" ", text)

    expected_portable = remove_spaces(make_portable(expected))
    actual_portable = remove_spaces(make_portable(actual))
    return expected_portable in actual_portable


def make_portable(object: Any) -> Any:
    if isinstance(object, (str, bytes)):
        return make_portable_text(object)
    elif isinstance(object, dict):
        return {k: make_portable(v) for k, v in object.items()}  # type: ignore
    elif isinstance(object, list):
        return [make_portable(v) for v in object]  # type: ignore
    elif isinstance(object, tuple):
        return tuple(make_portable(v) for v in object)  # type: ignore
    else:
        return object


def make_portable_text(text: str | bytes) -> str | bytes:
    def replace_with_zeroes_str(match: re.Match[str]) -> str:
        num_zeroes = len(match.group(0)[2:])
        return f"0x{'0' * num_zeroes}"

    def replace_with_zeros_bytes(match: re.Match[bytes]) -> bytes:
        num_zeroes = len(match.group(0)[2:])
        return b"0x" + b"0" * num_zeroes

    if isinstance(text, str):
        # Remove addresses
        text = re.sub(r"0x[a-f0-9]{10,}+", replace_with_zeroes_str, text)
        # Remove spent time
        text = re.sub(r"[elapsed|cpu]=[0-9.]+s", "elapsed=Xs", text)
        text = re.sub(r"[elapsed|cpu]=[0-9.]+ms", "elapsed=Xms", text)
    else:  # bytes
        # Remove addresses
        text = re.sub(rb"0x[a-f0-9]{10,}+", replace_with_zeros_bytes, text)
        # Remove spent time
        text = re.sub(rb"[elapsed|cpu]=[0-9.]+s", b"elapsed=Xs", text)
        text = re.sub(rb"[elapsed|cpu]=[0-9.]+ms", b"elapsed=Xms", text)

    # Remove system-dependent directories
    for directory, placeholder in [
        (PACKAGES_DIRECTORY, "$PACKAGE_DIR"),
        (Path.cwd(), "$CURDIR"),
        (Path.home(), "$HOME"),
    ]:
        if isinstance(text, str):
            while str(directory) in text:
                text = text.replace(str(directory), placeholder)
        else:  # bytes
            while str(directory).encode() in text:
                text = text.replace(str(directory).encode(), placeholder.encode())

    if isinstance(text, str):
        text = re.sub(r"/tmp/tmp[^/\s]+", "$TMPFILE", text)
    else:  # bytes
        text = re.sub(rb"/tmp/tmp[^/\s]+", b"$TMPFILE", text)
    return text


def revert_portable(object: Any) -> Any:
    if isinstance(object, (str, bytes)):
        return revert_portable_text(object)
    elif isinstance(object, dict):
        return {k: revert_portable(v) for k, v in object.items()}  # type: ignore
    elif isinstance(object, list):
        return [revert_portable(v) for v in object]  # type: ignore
    elif isinstance(object, tuple):
        return tuple(revert_portable(v) for v in object)  # type: ignore
    else:
        return object


def revert_portable_text(text: str | bytes) -> str | bytes:
    # Recover system-dependent directories
    for directory, placeholder in [
        (PACKAGES_DIRECTORY, "$PACKAGE_DIR"),
        (Path.cwd(), "$CURDIR"),
        (Path.home(), "$HOME"),
    ]:
        if isinstance(text, str):
            while placeholder in text:
                text = text.replace(placeholder, str(directory))
        else:  # bytes
            while placeholder.encode() in text:
                text = text.replace(placeholder.encode(), str(directory).encode())

    return text


def build_aixcc_context(
    challenge_project_directory: Path, detection_file: Path, **kwargs: Any
) -> tuple[AgentContext, Detection]:
    return AIxCCContextBuilder(
        challenge_project_directory,
        detection_file,
        **kwargs,
    ).build(
        previous_action=HeadAction(),
    )
