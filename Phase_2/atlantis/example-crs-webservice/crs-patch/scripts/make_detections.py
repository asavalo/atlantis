import argparse
import base64
import json
import os
import re
from pathlib import Path

from python_aixcc_challenge.detection.models import (
    AIxCCChallengeBlobInfo,
    AIxCCChallengeDeltaMode,
    AIxCCChallengeFullMode,
    AIxCCChallengeMode,
    AIxCCChallengeProjectDetection,
)
from python_aixcc_challenge.project.models import (
    AIxCCChallengeProjectConfig,
    DeltaModeConfig,
    FullModeConfig,
)

MODES = ["full", "delta", "sarif-only", "sarif-pov"]

IGNORED_PROJECTS = [
    # LSP projects
    r".*lsp.*",
]

FDP_HARNESS_PATTERNS = [
    # FDP harness bugs are identical to the non-FDP harness bugs
    r".*FDP.*",
    r".*fdp.*",
]

DEACTIVATED_VULNERABILITY_IDENTIFIERS = [
    r"^.*-jvm-htmlunit-.*$",
    r"^.*-jvm-ztzip-.*$",
    r"^.*-jvm-aerospike-.*$",
    r"^.*-jvm-geonetwork-.*$",
]


def make_vulnerability_identifier(project_name: str, cpv_name: str, mode: str) -> str:
    prefix = None
    if re.match(r"aixcc\/(c|cpp)\/(\w+)-(\d+)", project_name):
        prefix = "arvo"
    elif (
        project_name.endswith("asc-nginx")
        or project_name.endswith("mock-cp")
        or project_name.endswith("libpng")
        or (
            project_name == "aixcc/jvm/jenkins"
            # and harness_name == "JenkinsTwo"
            and cpv_name == "cpv_1"
        )
    ):
        prefix = "official"
    else:
        prefix = "custom"

    language = project_name.split("/")[1]
    the_project_name = project_name.split("/")[2]

    vi = f"{prefix}-{language}-{the_project_name}-{cpv_name}-{mode}"
    return vi.replace("_", "-")


def make_mode(mode_config: FullModeConfig | DeltaModeConfig) -> AIxCCChallengeMode:
    match mode_config:
        case FullModeConfig():
            return AIxCCChallengeFullMode(type="full", base_ref=mode_config.base_commit)
        case DeltaModeConfig():
            return AIxCCChallengeDeltaMode(
                type="delta",
                base_ref=mode_config.base_commit,
                delta_ref=mode_config.ref_commit,
            )


def load_blobs(project_name: str, harness_name: str, cpv_name: str) -> list[str]:
    blobs: list[str] = []
    blob_path = Path(
        f"packages/python_oss_fuzz/.oss_fuzz/projects/{project_name}/.aixcc/povs/{harness_name}/{cpv_name}"
    )
    with open(blob_path, "rb") as f:
        blob = base64.b64encode(f.read()).decode(errors="replace")
        blobs.append(blob)

    for file in Path(
        f"packages/python_oss_fuzz/.oss_fuzz/projects/{project_name}/.aixcc/pov_variants"
    ).glob(f"{cpv_name}_*"):
        with open(file, "rb") as f:
            blob = base64.b64encode(f.read()).decode(errors="replace")
            blobs.append(blob)

    return blobs


def load_sarif_report(
    project_name: str, harness_name: str, cpv_name: str
) -> str | None:
    language = project_name.split(os.sep)[1]
    target_name = project_name.split(os.sep)[2]
    sarif_path = Path(
        f"third_party/SARIF/benchmarks/manual/true/[{language}][{target_name}][{harness_name}][{cpv_name}].sarif"
    )
    if not sarif_path.exists():
        return None

    with open(sarif_path, "r") as f:
        return json.dumps(json.load(f))


def is_ignored_project(project_name: str) -> bool:
    for pattern in IGNORED_PROJECTS:
        if re.match(pattern, project_name):
            return True
    return False


def is_fdp_harness(harness_name: str) -> bool:
    for pattern in FDP_HARNESS_PATTERNS:
        if re.match(pattern, harness_name):
            return True
    return False


def get_ignored_harness_names(project_config: AIxCCChallengeProjectConfig) -> list[str]:
    """
    Handling this way as the way `FDP` is appended to the harness name is not consistent.
    For example,
        - `ActivemqOneFDP` and `ActivemqOne`.
        - `pem_fdp` and `pem`.
    This checks if there is any harness name a complete substring of a fdp harness name.
    """
    fdp_harness_names: list[str] = []
    for harness_details in project_config.harness_files:
        if is_fdp_harness(harness_details.name):
            fdp_harness_names.append(harness_details.name)

    ignored_harness_names: list[str] = []
    for harness_details in project_config.harness_files:
        if any(
            harness_details.name in fdp_harness_name
            for fdp_harness_name in fdp_harness_names
        ):
            ignored_harness_names.append(harness_details.name)

    # Remove FDP harness names from ignored list
    ignored_harness_names = [
        name for name in ignored_harness_names if name not in fdp_harness_names
    ]

    return ignored_harness_names


def is_deactivated_vulnerability_identifier(vulnerability_identifier: str) -> bool:
    for pattern in DEACTIVATED_VULNERABILITY_IDENTIFIERS:
        if re.match(pattern, vulnerability_identifier):
            return True
    return False


def make_detection(
    project_name: str,
    cpv_name: str,
    project_config: AIxCCChallengeProjectConfig,
    mode: str,
):
    match mode:
        case "full":
            mode_config = project_config.full_mode
            include_sarif_report = False
            include_blobs = True
        case "delta":
            if project_config.delta_mode and len(project_config.delta_mode) > 0:
                mode_config = project_config.delta_mode[0]
            else:
                print(f"No delta mode config for {project_name} {cpv_name}")
                return
            include_sarif_report = False
            include_blobs = True
        case "sarif-only":
            mode_config = project_config.full_mode
            include_sarif_report = True
            include_blobs = False
        case "sarif-pov":
            mode_config = project_config.full_mode
            include_sarif_report = True
            include_blobs = True
        case _:
            raise ValueError(f"Invalid mode: {mode}")

    vulnerability_identifier = make_vulnerability_identifier(
        project_name, cpv_name, mode
    )

    # Determine detection path
    detection_path = Path(f"scripts/benchmark/full/{vulnerability_identifier}.toml")

    if is_deactivated_vulnerability_identifier(vulnerability_identifier):
        detection_path = detection_path.with_name(f"_{detection_path.name}")

    ignored_harness_names = get_ignored_harness_names(project_config)

    sarif_report = None
    if include_sarif_report:
        for harness_details in project_config.harness_files:
            sarif_report = load_sarif_report(
                project_name, harness_details.name, cpv_name
            )
            if sarif_report is not None:
                break
        if sarif_report is None:
            print(f"No sarif report for {vulnerability_identifier}")
            return

    blobs: list[AIxCCChallengeBlobInfo] = []
    if include_blobs:
        for harness_details in project_config.harness_files:
            if (
                # The `not include_sarif_report` condition is to filter out non-FDP harnesses
                # only when the mode is either `full` or `delta`.
                not include_sarif_report
                and harness_details.name in ignored_harness_names
            ):
                continue
            if harness_details.cpvs is None:
                continue
            matching_cpvs = [c for c in harness_details.cpvs if c.name == cpv_name]
            if len(matching_cpvs) == 0:
                continue
            cpv = matching_cpvs[0]
            blobs.extend(
                AIxCCChallengeBlobInfo(
                    harness_name=harness_details.name,
                    sanitizer_name=cpv.sanitizer,
                    blob=blob,
                )
                for blob in load_blobs(project_name, harness_details.name, cpv_name)
            )

    detection = AIxCCChallengeProjectDetection(
        vulnerability_identifier=vulnerability_identifier,
        project_name=project_name,
        sarif_report=sarif_report,
        blobs=blobs,
        mode=make_mode(mode_config),
    )

    save_detection(detection_path, detection)


def save_detection(detection_path: Path, detection: AIxCCChallengeProjectDetection):
    detection_content = detection.to_toml()
    detection_content = (
        "# DO NOT EDIT THIS FILE.\n"
        "# This file is automatically generated by `scripts/make_detections.py`\n\n"
        + detection_content
    )
    detection_path.write_text(detection_content)
    print(f"Stored {detection_path}")


ap = argparse.ArgumentParser(
    description="How to run: $ uv run scripts/make_detections.py packages/python_oss_fuzz/.oss_fuzz/projects/aixcc/*/*/.aixcc/config.yaml"
)
ap.add_argument(
    "-d",
    "--delete",
    action="store_true",
    default=False,
    help="Delete the detection files",
)
ap.add_argument(
    "config_paths",
    nargs="+",
    type=Path,
    help="Path to the config.yaml file for each project",
)
args = ap.parse_args()

if args.delete:
    print("Deleting detection files...")
    for mode in MODES:
        for detection_path in Path(f"scripts/benchmark/{mode}").glob("**/*.toml"):
            detection_path.unlink()


Path("scripts/benchmark/full").mkdir(parents=True, exist_ok=True)

for config_path in args.config_paths:
    if not config_path.exists() or config_path.name != "config.yaml":
        raise ValueError(f"Invalid config path: {config_path}")

    m = re.search(r"(aixcc\/(c|cpp|jvm)\/[a-z0-9_-]+)", config_path.as_posix())
    if not m:
        other_languages = ["go", "javascript", "python", "rust", "swift"]
        if any(f"aixcc/{lang}" in config_path.as_posix() for lang in other_languages):
            continue
        raise ValueError(f"Invalid config path: {config_path}")

    project_name = m.group(1)

    if is_ignored_project(project_name):
        continue
    print(f"Processing {project_name}")

    project_config = AIxCCChallengeProjectConfig.from_project_name(project_name)

    cpv_names = {
        cpv.name
        for harness in project_config.harness_files
        if harness.cpvs is not None
        for cpv in harness.cpvs
    }

    for mode in MODES:
        for cpv_name in cpv_names:
            make_detection(project_name, cpv_name, project_config, mode)

print("Done!")
