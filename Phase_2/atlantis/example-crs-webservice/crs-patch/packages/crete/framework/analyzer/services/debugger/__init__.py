import os
import pty
import subprocess
from pathlib import Path
from typing import Callable, cast

from python_oss_fuzz.gdb.functions import copy_gdb_binary, copy_gdb_scripts
from python_oss_fuzz.path.globals import (
    OSS_FUZZ_BASE_IMAGE_TAG,
    OSS_FUZZ_DEBUGGER_OUT_DIRECTORY,
    OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY,
    OSS_FUZZ_DIRECTORY,
)

from crete.atoms.detection import Detection
from crete.commons.docker.functions import docker_shell
from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.evaluator.contexts import EvaluatingContext

from .models import Breakpoint
from .scripts import (
    FILE_LINE_BREAKPOINT_SCRIPT_TEMPLATE,
    FUNCTION_BREAKPOINT_SCRIPT_TEMPLATE,
    GDB_SCRIPT_TEMPLATE,
    WRAPPER_SCRIPT_TEMPLATE,
)


class DebuggerAnalyzer:
    """
        A debugger that runs a PoV with breakpoints. The debugger is intended to
        offer runtime inspection for the provided PoV.

    Methods:
        - analyze: Operates on a debug-enabled build, executes a PoV with
          breakpoints, capturing and returning traced expressions
          (breakpoints[].expressions) at each breakpoint. The expressions are
          returned as a string.
    """

    def __init__(self):
        if not OSS_FUZZ_DEBUGGER_OUT_DIRECTORY.exists():
            OSS_FUZZ_DEBUGGER_OUT_DIRECTORY.mkdir(parents=True)
        if not OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY.exists():
            OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY.mkdir(parents=True)

    def analyze(
        self,
        context: EvaluatingContext,
        detection: Detection,
        breakpoints: list[Breakpoint] = [],
        additional_gdb_script: str = "",
    ) -> str | None:
        cache_function = cast(
            Callable[..., str | None],
            context["memory"].cache(self._analyze_no_cache, ignore=["context"]),  # pyright: ignore[reportUnknownMemberType]
        )
        return cache_function(context, detection, breakpoints, additional_gdb_script)

    def _analyze_no_cache(
        self,
        context: EvaluatingContext,
        detection: Detection,
        breakpoints: list[Breakpoint] = [],
        additional_gdb_script: str = "",
    ) -> str | None:
        environment = context["pool"].use(context, "DEBUG")
        if environment is None:
            context["logger"].warning("No debug environment found")
            return None

        breakpoints_out, _, _ = self._run_pov_with_breakpoints(
            context, detection, breakpoints, additional_gdb_script
        )

        return breakpoints_out

    def _run_pov_with_breakpoints(
        self,
        context: EnvironmentContext,
        detection: Detection,
        breakpoints: list[Breakpoint],
        additional_gdb_script: str,
    ) -> tuple[str, str, str]:
        required_files = _prepare_files(detection, breakpoints, additional_gdb_script)
        breakpoints_out_path = required_files["breakpoints_out_path"]
        wrapper_script_path = required_files["wrapper_script_path"]

        stdout, stderr = _run_oss_fuzz_debugger(wrapper_script_path)

        context["logger"].debug("=== base-runner-debug stdout ===")
        context["logger"].debug(stdout)
        context["logger"].debug("=================================")

        return breakpoints_out_path.read_text(), stdout, stderr


def _prepare_files(
    detection: Detection, breakpoints: list[Breakpoint], additional_gdb_script: str
) -> dict[str, Path]:
    """
    Prepare files (PoC file, gdb output, gdb script, wrapper script) for the
    debugger to run.

    Returns:
        - breakpoints_out_path: The file path of gdb output file.
        - wrapper_script_path: The file path of the wrapper script file.

    All files are written to the work_directory.
    """
    breakpoint_outs_path = OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY / "breakpoints-out"
    breakpoint_outs_path.unlink(missing_ok=True)

    assert len(detection.blobs) > 0, "At least one blob is required"
    poc_path = OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY / "poc"
    poc_path.write_bytes(detection.blobs[0].blob)

    gdb_script_path = OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY / "gdb_script"
    gdb_script = _generate_gdb_script(
        breakpoints, breakpoint_outs_path, additional_gdb_script
    )
    gdb_script_path.write_text(gdb_script)

    wrapper_script_path = OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY / "wrapper_script"
    wrapper_script = _generate_wrapper_script(detection, gdb_script_path, poc_path)
    wrapper_script_path.write_text(wrapper_script)
    os.chmod(wrapper_script_path, 0o755)

    copy_gdb_scripts()
    copy_gdb_binary()

    return {
        "breakpoints_out_path": breakpoint_outs_path,
        "wrapper_script_path": wrapper_script_path,
    }


def _generate_gdb_script(
    breakpoints: list[Breakpoint],
    breakpoints_out_path: Path,
    additional_gdb_script: str,
) -> str:
    breakpoints_script = _generate_breakpoints_script(breakpoints)
    return GDB_SCRIPT_TEMPLATE.format(
        breakpoints_out=_host_to_container_work_path(breakpoints_out_path),
        breakpoints_script=breakpoints_script,
        additional_gdb_script=additional_gdb_script,
    )


def _generate_wrapper_script(
    detection: Detection,
    gdb_script_path: Path,
    poc_path: Path,
) -> str:
    assert len(detection.blobs) > 0, "At least one blob is required"
    return WRAPPER_SCRIPT_TEMPLATE.format(
        project_name=detection.project_name,
        harness_name=detection.blobs[0].harness_name,
        gdb_script=_host_to_container_work_path(gdb_script_path),
        poc=_host_to_container_work_path(poc_path),
    )


def _generate_breakpoints_script(breakpoints: list[Breakpoint]) -> str:
    scripts: list[str] = []
    for index, breakpoint in enumerate(breakpoints, start=1):
        match breakpoint["location"]:
            case (file, line):
                breakpoint_script = FILE_LINE_BREAKPOINT_SCRIPT_TEMPLATE.format(
                    file=file,
                    line=line,
                    index=index,
                    expressions="\n".join(breakpoint["expressions"]),
                )
            case function_name:
                breakpoint_script = FUNCTION_BREAKPOINT_SCRIPT_TEMPLATE.format(
                    function=function_name,
                    index=index,
                    expressions="\n".join(breakpoint["expressions"]),
                )
        scripts.append(breakpoint_script)
    return "\n".join(scripts)


def _run_oss_fuzz_debugger(wrapper_script_path: Path) -> tuple[str, str]:
    # We need tty to run the docker container interactively
    # https://github.com/google/oss-fuzz/blob/1188a704bab8df943b0b2faaa63d5e6bdcb8fcc0/infra/helper.py#L733
    master_fd, slave_fd = pty.openpty()
    process = docker_shell(
        image=f"ghcr.io/aixcc-finals/base-runner-debug:{OSS_FUZZ_BASE_IMAGE_TAG}",
        out_directory=OSS_FUZZ_DEBUGGER_OUT_DIRECTORY,
        work_directory=OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY,
        cwd=OSS_FUZZ_DIRECTORY,
        stdin=slave_fd,
    )

    wrapper_script_container_path = _host_to_container_work_path(wrapper_script_path)
    command = f"{wrapper_script_container_path}; exit\n"
    os.write(master_fd, command.encode())

    try:
        outs, errs = process.communicate(timeout=10)
    except subprocess.TimeoutExpired as e:
        outs = e.stdout or b""
        errs = e.stderr or b""

    os.close(master_fd)
    os.close(slave_fd)
    process.kill()

    return outs.decode(errors="replace"), errs.decode(errors="replace")


def _host_to_container_work_path(path: Path) -> Path:
    """
    OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY is mounted to /work in the docker container.
    This function converts host paths to container paths.
    """
    assert path.is_absolute(), "Path must be absolute"
    assert path.is_relative_to(OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY), (
        "Path must be under OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY"
    )
    return Path("/work") / path.relative_to(OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY)
