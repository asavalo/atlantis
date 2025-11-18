from pathlib import Path

from crete.commons.interaction.functions import run_command

from ..path.globals import OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY

# from python_rr import RR_BACKTRACER_REPO_PATH, RR_HOME_PATH


# This file is not used because `python_rr` is now deprecated.
# These variables are just defined to avoid import errors.
RR_HOME_PATH = Path(__file__).parent / "python_rr" / "bin" / "rr"
RR_BACKTRACER_REPO_PATH = Path.home() / ".cache" / "crete" / "backtracer"

# rr-backtracer's git repo URL.
RR_BACKTRACER_URL = "git@github.com:Team-Atlanta/rr-backtracer.git"


def copy_rr_backtracer():
    # @TODO: better way to download rr-backtracer tool? Registering it in `pyproject.toml` might be an answer.
    # Unlike other git repos, however, rr-backtracer is not a tool or library directly used by crete.
    run_command(
        (
            f"cp -r {RR_BACKTRACER_REPO_PATH} backtracer",
            OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY,
        )
    )


def copy_rr_dir():
    """
    Copy crete's rr directory to OSS-Fuzz's working directory.
    Unlike crete's gdb, which is built statically, rr debugger requires all of its shared libraries to be present.
    Thus, we should copy all the contents.
    """
    assert RR_HOME_PATH.exists(), f"{RR_HOME_PATH} does not exist"

    rr_ossfuzz_path = OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY / "rr"

    if rr_ossfuzz_path.exists():
        return

    run_command(
        (
            f"cp -r {RR_HOME_PATH} {rr_ossfuzz_path}",
            OSS_FUZZ_DEBUGGER_WORKING_DIRECTORY,
        )
    )
