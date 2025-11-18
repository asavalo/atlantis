from pathlib import Path

from crete.commons.interaction.functions import run_command
from python_gdb_static import GDB_EXECUTABLE_FILE

from ..path.globals import OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY


def copy_gdb_scripts():
    gdb_scripts_directory = Path(__file__).parent / "scripts"
    oss_fuzz_gdb_scripts_dir = OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY / "gdb_scripts"

    run_command((f"rm -rf {oss_fuzz_gdb_scripts_dir}", Path(".")))
    run_command(
        (
            f"cp -rf {gdb_scripts_directory} {oss_fuzz_gdb_scripts_dir}",
            Path("."),
        )
    )


def copy_gdb_binary():
    assert GDB_EXECUTABLE_FILE.exists(), f"{GDB_EXECUTABLE_FILE} does not exist"
    gdb_binary_path = OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY / "gdb"
    run_command(
        (
            f"cp {GDB_EXECUTABLE_FILE} {gdb_binary_path}",
            Path("."),
        )
    )
