import argparse
import logging
import os
from pathlib import Path

import requests
import yaml

# Configure logging properly
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def _filter_projects_by_language(oss_fuzz_dir: str, language: str) -> list[str]:
    oss_fuzz_path = Path(oss_fuzz_dir)
    projects = [p.name for p in oss_fuzz_path.glob("projects/*")]

    logger.info(f"Found {len(projects)} projects in {oss_fuzz_dir}")

    filtered_projects = []
    for project in projects:
        if project == "aixcc":
            continue

        config_path = oss_fuzz_path / "projects" / project / "project.yaml"
        if not os.path.exists(config_path):
            continue

        with open(config_path, "r") as f:
            try:
                config = yaml.safe_load(f)
                if config.get("language") == language:
                    filtered_projects.append(project)
            except yaml.YAMLError as e:
                logger.warning(f"Failed to parse YAML for project {project}: {e}")
                continue

    logger.info(f"Found {len(filtered_projects)} projects with language {language}")
    return filtered_projects


def _get_harnesses(project_name: str) -> list[str]:
    url = f"https://introspector.oss-fuzz.com/api/harness-source-and-executable?project={project_name}"
    try:
        logger.debug(f"Calling API for project {project_name}: {url}")
        response = requests.get(url, headers={"accept": "application/json"})

        if response.status_code != 200:
            logger.warning(
                f"API request failed for {project_name}: {response.status_code}"
            )
            return []

        data = response.json()
        logger.debug(f"API response: {data}")
        if data.get("result") != "success":
            logger.warning(
                f"API returned error for {project_name}: {data.get('result')}"
            )
            return []

        pairs = data.get("pairs", [])
        logger.debug(f"Found {len(pairs)} executables for {project_name}")
        return pairs
    except Exception as e:
        logger.error(f"Error calling API for {project_name}: {e}")
        return []


if __name__ == "__main__":
    logger.info("Starting script")

    parser = argparse.ArgumentParser()
    parser.add_argument("--oss_fuzz_dir", type=str, required=True)
    parser.add_argument("--language", type=str, required=True)
    parser.add_argument("--output_dir", type=str, required=True)
    args = parser.parse_args()

    logger.info(
        f"Arguments: oss_fuzz_dir={args.oss_fuzz_dir}, language={args.language}, output_dir={args.output_dir}"
    )

    # Check if directories exist
    if not os.path.exists(args.oss_fuzz_dir):
        logger.error(f"OSS-Fuzz directory does not exist: {args.oss_fuzz_dir}")
        exit(1)

    if not os.path.exists(args.output_dir):
        logger.info(f"Creating output directory: {args.output_dir}")
        os.makedirs(args.output_dir, exist_ok=True)

    projects = _filter_projects_by_language(args.oss_fuzz_dir, args.language)

    logger.info(f"Found {len(projects)} projects with language {args.language}")

    compileable_projects = []
    for project in projects:
        logger.info(f"Checking harnesses for {project}")
        harnesses = _get_harnesses(project)
        if len(harnesses) > 0:
            compileable_projects.append(
                {"project": project, "harnesses": harnesses}
            )

    logger.info(f"Found {len(compileable_projects)} compileable projects")

    # save list of compileable projects to file
    output_file = os.path.join(
        args.output_dir, f"{args.language}_compileable_projects.txt"
    )
    logger.info(f"Saving list of compileable projects to {output_file}")
    with open(output_file, "w") as f:
        for project in compileable_projects:
            f.write(project["project"] + "\n")

    # make .aixcc/config.yaml file
    for project in compileable_projects:
        logger.info(f"Generating .aixcc/config.yaml for {project['project']}")

        config_path = (
            Path(args.oss_fuzz_dir)
            / "projects"
            / project["project"]
            / ".aixcc"
            / "config.yaml"
        )
        logger.info(f"Config path: {config_path}")
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_data = {"harness_files": []}

        for harness in project["harnesses"]:
            harness_name = harness["executable"]
            harness_path = harness["source"]
            config_data["harness_files"].append(
                {"name": harness_name, "path": harness_path}
            )

        with open(config_path, "w") as f:
            yaml.dump(config_data, f, default_flow_style=False)

    logger.info("Script completed successfully")
