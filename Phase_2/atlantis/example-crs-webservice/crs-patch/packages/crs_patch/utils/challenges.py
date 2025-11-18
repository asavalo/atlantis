import os
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Literal, Optional

from python_aixcc_challenge.detection.models import (
    AIxCCChallengeDeltaMode,
    AIxCCChallengeFullMode,
    AIxCCChallengeMode,
)
from python_oss_fuzz.path.globals import OSS_FUZZ_PROJECTS_DIRECTORY

SOURCE_DIRECTORY = Path.home() / "cp_sources"


def setup_challenge_project(
    tarfile_directory: Path,
    output_directory: Path,
) -> Path:
    repo_tarfile = tarfile_directory / "repo.tar.gz"
    if not repo_tarfile.exists():
        raise ValueError(f"Repo tarfile {repo_tarfile} does not exist")

    diff_tarfile = tarfile_directory / "diff.tar.gz"
    if not diff_tarfile.exists():
        diff_tarfile = None

    if (tarfile_directory / "oss-fuzz.tar.gz").exists():
        oss_fuzz_tarfile = tarfile_directory / "oss-fuzz.tar.gz"
        _extract_tarfile(oss_fuzz_tarfile, output_directory)
        _update_timestamps(output_directory / "fuzz-tooling")

    return setup_challenge_project_from_tarfiles(
        repo_tarfile, output_directory, diff_tarfile
    )


def setup_challenge_project_from_tarfiles(
    source_tarfile: Path,
    output_directory: Path = SOURCE_DIRECTORY,
    diff_tarfile: Optional[Path] = None,
) -> Path:
    # Extract the project source tarball
    source_directory = _extract_repo_tarfile(source_tarfile, output_directory)
    _update_timestamps(source_directory)

    subprocess.check_call(f"git init {source_directory}", shell=True)
    subprocess.check_call(
        f"git config --global --add safe.directory {source_directory}", shell=True
    )
    subprocess.check_call(
        "git add --all -f && git commit -m 'Initial commit'",
        cwd=source_directory,
        shell=True,
    )

    if diff_tarfile is not None:
        # Extract the diff tarball
        _extract_tarfile(diff_tarfile, output_directory)

        diff_file = output_directory / "diff" / "ref.diff"

        # git apply --reject may not be able to apply all changes, and return non-zero exit code
        subprocess.run(
            f"git apply --reject {diff_file}", cwd=source_directory, shell=True
        )
        subprocess.check_call(
            "git add --all -f && git commit -m 'Update changes'",
            cwd=source_directory,
            shell=True,
        )

    return source_directory


def setup_oss_fuzz_projects(output_directory: Path = SOURCE_DIRECTORY):
    projects_directory = output_directory / "fuzz-tooling" / "projects"
    target_directory = OSS_FUZZ_PROJECTS_DIRECTORY
    subprocess.run(
        f"rsync -a --delete {projects_directory}/ {target_directory}", shell=True
    )


def construct_challenge_mode(
    challenge_project_directory: Path, mode: Literal["full", "delta"]
) -> AIxCCChallengeMode:
    match mode:
        case "full":
            base_ref = subprocess.check_output(
                "git rev-parse HEAD",
                cwd=challenge_project_directory,
                shell=True,
                text=True,
            ).strip()
            challenge_mode = AIxCCChallengeFullMode.model_validate(
                {
                    "type": "full",
                    "base_ref": base_ref,
                }
            )
        case "delta":
            base_ref = subprocess.check_output(
                "git rev-parse HEAD~",
                cwd=challenge_project_directory,
                shell=True,
                text=True,
            ).strip()
            delta_ref = subprocess.check_output(
                "git rev-parse HEAD",
                cwd=challenge_project_directory,
                shell=True,
                text=True,
            ).strip()
            challenge_mode = AIxCCChallengeDeltaMode.model_validate(
                {
                    "type": "delta",
                    "base_ref": base_ref,
                    "delta_ref": delta_ref,
                }
            )
    return challenge_mode


def _extract_repo_tarfile(tar_path: Path, output_directory: Path):
    output_directory.mkdir(parents=True, exist_ok=True)
    members = _extract_tarfile(tar_path, output_directory)

    return output_directory / members[0].name


def _extract_tarfile(tar_path: Path, output_directory: Path):
    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(output_directory)
        return tar.getmembers()


def _update_timestamps(root_dir: Path):
    """
    Recursively updates all file and directory timestamps under `root_dir`
    to the current time to avoid ZIP timestamp issues.
    """
    current_time = time.time()

    # Walk from the bottom up to handle directories after files
    for dirpath, dirnames, filenames in os.walk(root_dir, topdown=False):
        for name in filenames:
            file_path = os.path.join(dirpath, name)
            os.utime(file_path, (current_time, current_time))

        for name in dirnames:
            dir_path = os.path.join(dirpath, name)
            os.utime(dir_path, (current_time, current_time))

    os.utime(root_dir, (current_time, current_time))
