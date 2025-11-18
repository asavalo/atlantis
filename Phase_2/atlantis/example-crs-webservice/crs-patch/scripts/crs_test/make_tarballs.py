import argparse
import subprocess
from pathlib import Path

from python_aixcc_challenge.detection.models import (
    AIxCCChallengeDeltaMode,
    AIxCCChallengeFullMode,
    AIxCCChallengeProjectDetection,
)
from python_aixcc_challenge.project.models import AIxCCChallengeProjectYaml

TARBALL_DIRECTORY = Path("./cp_tarballs")
REPO_DIRECTORY = Path(__file__).parent / "repositories"
CACHE_DIRECTORY = Path(__file__).parent / ".cache"


def prepare_repository(git_url: str, repository_directory: Path):
    repository_directory.parent.mkdir(parents=True, exist_ok=True)
    print(f"Preparing {repository_directory}")
    if repository_directory.exists():
        subprocess.check_call(
            f"git -C {repository_directory} fetch --recurse-submodules",
            shell=True,
        )
        subprocess.check_call(
            f"git -C {repository_directory} reset --hard origin/HEAD && git -C {repository_directory} clean -fd",
            shell=True,
        )
    else:
        subprocess.check_call(
            f"git clone --recurse-submodules {git_url} {repository_directory}",
            shell=True,
        )


def remove_directory(directory: Path):
    subprocess.check_call(
        f"rm -rf {directory}",
        shell=True,
    )


def prepare_repo(project_yaml: AIxCCChallengeProjectYaml):
    git_url = project_yaml.main_repo
    project_name = git_url.split("/")[-1].replace(".git", "")
    prepare_repository(git_url, REPO_DIRECTORY / project_name)
    return REPO_DIRECTORY / project_name


def prepare_oss_fuzz():
    prepare_repository(
        "https://github.com/Team-Atlanta/oss-fuzz", REPO_DIRECTORY / "oss-fuzz"
    )
    return REPO_DIRECTORY / "oss-fuzz"


def make_repo_tarball(
    source_directory: Path,
    oss_fuzz_directory: Path,
    tarball_directory: Path,
    detection_yaml: AIxCCChallengeProjectDetection,
):
    assert source_directory.exists(), (
        f"Source directory {source_directory} does not exist"
    )
    assert oss_fuzz_directory.exists(), (
        f"OSS-Fuzz directory {oss_fuzz_directory} does not exist"
    )

    temp_repo_directory = CACHE_DIRECTORY / source_directory.name
    temp_diff_directory = CACHE_DIRECTORY / "diff"
    temp_oss_fuzz_directory = CACHE_DIRECTORY / "fuzz-tooling"

    remove_directory(temp_repo_directory)
    remove_directory(temp_diff_directory)
    remove_directory(temp_oss_fuzz_directory)
    remove_directory(tarball_directory)

    tarball_directory.mkdir(parents=True, exist_ok=True)

    # git checkout for fullmode
    if isinstance(detection_yaml.mode, AIxCCChallengeFullMode):
        subprocess.check_call(
            f"cp -r {source_directory} {temp_repo_directory}",
            shell=True,
        )
        subprocess.check_call(
            f"git -C {temp_repo_directory} checkout {detection_yaml.mode.checkout_ref()}",
            shell=True,
        )
        remove_aixcc_git_directory(temp_repo_directory)
        subprocess.check_call(
            f"tar cvfz {tarball_directory / 'repo.tar.gz'} -C {CACHE_DIRECTORY} {temp_repo_directory.name}",
            shell=True,
        )
    elif isinstance(detection_yaml.mode, AIxCCChallengeDeltaMode):
        subprocess.check_call(
            f"cp -r {source_directory} {temp_repo_directory}",
            shell=True,
        )
        subprocess.check_call(
            f"cp -r {source_directory} {temp_repo_directory}-diff",
            shell=True,
        )
        subprocess.check_call(
            f"git -C {temp_repo_directory} checkout {detection_yaml.mode.base_ref}",
            shell=True,
        )
        subprocess.check_call(
            f"git -C {temp_repo_directory}-diff checkout {detection_yaml.mode.delta_ref}",
            shell=True,
        )
        remove_aixcc_git_directory(temp_repo_directory)
        remove_aixcc_git_directory(
            temp_repo_directory.with_name(temp_repo_directory.name + "-diff")
        )
        temp_diff_directory.mkdir(parents=True, exist_ok=True)

        # Generate diff between base and delta versions
        sed_patterns = [
            f"s|a{temp_repo_directory}|a|g",
            f"s|b{temp_repo_directory}-diff|b|g",
            f"s|b{temp_repo_directory}|b|g",
            f"s|a{temp_repo_directory}-diff|a|g",
            f"s| {temp_repo_directory}/| |g",
            f"s| {temp_repo_directory}-diff/| |g",
        ]
        sed_cmd = " | ".join(f"sed '{pattern}'" for pattern in sed_patterns)
        cmd = f"git diff --no-index {temp_repo_directory} {temp_repo_directory}-diff | {sed_cmd} > {temp_diff_directory / 'ref.diff'}"
        subprocess.check_call(
            cmd,
            shell=True,
        )
        subprocess.check_call(
            f"tar cvfz {tarball_directory / 'diff.tar.gz'} -C {CACHE_DIRECTORY} {temp_diff_directory.name}",
            shell=True,
        )
        subprocess.check_call(
            f"tar cvfz {tarball_directory / 'repo.tar.gz'} -C {CACHE_DIRECTORY} {temp_repo_directory.name}",
            shell=True,
        )

    ## Oss-fuzz
    subprocess.check_call(
        f"cp -r {oss_fuzz_directory} {temp_oss_fuzz_directory}",
        shell=True,
    )
    remove_aixcc_git_directory(temp_oss_fuzz_directory)
    subprocess.check_call(
        f"rm -rf {temp_oss_fuzz_directory}/projects/*",
        shell=True,
    )
    subprocess.check_call(
        f"cp --parents -r {detection_yaml.project_name} {temp_oss_fuzz_directory}/projects/",
        cwd=oss_fuzz_directory / "projects",
        shell=True,
    )
    subprocess.check_call(
        f"tar cvfz {tarball_directory / 'oss-fuzz.tar.gz'} -C {CACHE_DIRECTORY} {temp_oss_fuzz_directory.name}",
        shell=True,
    )


def remove_aixcc_git_directory(directory: Path):
    subprocess.check_call(
        f"rm -rf {directory}/.git {directory}/.aixcc {directory}/.github",
        shell=True,
    )


def main(detection_file: Path):
    TARBALL_DIRECTORY.mkdir(parents=True, exist_ok=True)
    REPO_DIRECTORY.mkdir(parents=True, exist_ok=True)
    CACHE_DIRECTORY.mkdir(parents=True, exist_ok=True)

    detection_yaml = AIxCCChallengeProjectDetection.from_toml(detection_file)
    project_yaml = AIxCCChallengeProjectYaml.from_project_name(
        detection_yaml.project_name
    )
    tarball_directory = TARBALL_DIRECTORY / detection_yaml.project_name
    oss_fuzz_directory = prepare_oss_fuzz()
    repo_directory = prepare_repo(project_yaml)
    make_repo_tarball(
        repo_directory,
        oss_fuzz_directory,
        tarball_directory,
        detection_yaml,
    )

    print(f"Tarballs are in {tarball_directory}")
    print(f"TARBALL_DIRECTORY: {TARBALL_DIRECTORY}")
    print(f"Removing {CACHE_DIRECTORY}")
    remove_directory(CACHE_DIRECTORY)

    print(
        f"Run: ./docker-run.sh -l {project_yaml.language} -o {tarball_directory} -r {detection_yaml.project_name}"
    )


parser = argparse.ArgumentParser()
parser.add_argument("detection_file", type=Path)
args = parser.parse_args()

if __name__ == "__main__":
    main(args.detection_file)
