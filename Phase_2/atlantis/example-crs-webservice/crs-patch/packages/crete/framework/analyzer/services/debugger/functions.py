import json
import re
from pathlib import Path

from python_oss_fuzz.path.globals import OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY

from crete.atoms.detection import Detection
from crete.commons.interaction.functions import run_command
from crete.framework.evaluator.contexts import EvaluatingContext

from . import DebuggerAnalyzer
from .models import RuntimeValue


def dump_runtime_values(
    context: EvaluatingContext,
    detection: Detection,
    depth: int,
) -> list[dict[str, RuntimeValue]]:
    """
    Run GDB and dump runtime values in the call line of the crash stack.
    """
    result_filename = "runtime_values.json"

    # This is required because /src is not mounted, while the debugger inspects
    # the source code.
    _copy_src_to_out(context, detection)

    result_path_in_container = f"/work/{result_filename}"
    copied_src_path_in_container = f"/out/{detection.project_name}/src"

    additional_gdb_script = f"""
source /work/gdb_scripts/asan_debug.py
asan_debug {depth} {copied_src_path_in_container} {result_path_in_container}
quit
""".lstrip()

    debugger = DebuggerAnalyzer()
    debugger.analyze(context, detection, [], additional_gdb_script)
    result = json.loads(
        (OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY / result_filename).read_text()
    )

    return [
        {
            key: RuntimeValue(
                value=_strip_p_prefix(value["value"]),
                type=_strip_ptype_prefix(value["type"]),
            )
            for key, value in sorted(frame.items())
        }
        for frame in result
    ]


def _copy_src_to_out(context: EvaluatingContext, detection: Detection):
    """
    Copy the source code to the out directory.
    E.g.,
    src: /home/.../cp-user-nginx-asc-source
    dst: /home/.../oss-fuzz/build/out/nginx/src
    """
    _environment = context["pool"].restore(context)
    src_path = context["pool"].source_directory.resolve()
    out_path = context["pool"].out_directory / "src"
    if out_path.exists():
        return

    out_path.mkdir(parents=True)
    run_command((f"cp -rf {src_path} {out_path}", Path.cwd()))
    return


def _strip_p_prefix(value: str) -> str:
    return re.sub(r"^\$\d+ = ", "", value).strip()


def _strip_ptype_prefix(value: str) -> str:
    return re.sub(r"^type = ", "", value).strip()
