import argparse
import json
import os
import tarfile
import time
import uuid
from pathlib import Path

import docker
import docker.errors
import requests

from crs_sarif.models.models import (
    PatchMatchRequest,
    POVMatchRequest,
    SARIFMatchRequest,
)


def get_container_name(project_name: str) -> str:
    """
    Get the Docker container name for a project.

    Args:
        project_name (str): Name of the project

    Returns:
        str: Docker container name
    """
    return f"crs-sarif-{project_name}"


def get_container_port(project_name: str) -> int:
    """
    Get the exposed port from a Docker container based on project name.

    Args:
        project_name (str): Name of the project

    Returns:
        int: Exposed port number, or 4321 if container not found or no port exposed
    """
    container_name = get_container_name(project_name)
    client = docker.from_env()

    try:
        container = client.containers.get(container_name)

        # Get port mappings
        if container.ports:
            # Look for common HTTP ports (4000-5000 range, or any exposed port)
            for container_port, host_mappings in container.ports.items():
                if host_mappings:
                    # Return the first mapped host port
                    host_port = int(host_mappings[0]["HostPort"])
                    print(
                        f"Found container '{container_name}' running on port {host_port}"
                    )
                    return host_port

        print(
            f"Warning: Container '{container_name}' found but no port mappings detected"
        )
        return 4321

    except docker.errors.NotFound:
        print(
            f"Warning: Container '{container_name}' not found, using default port 4321"
        )
        return 4321
    except docker.errors.APIError as e:
        print(f"Warning: Error accessing Docker API: {e}, using default port 4321")
        return 4321
    except Exception as e:
        print(
            f"Warning: Unexpected error getting container port: {e}, using default port 4321"
        )
        return 4321


def _download_sarif_analysis_file(
    container_id: str,
    project_name: str,
    output_dir: str = "analysis_results",
    extra_wait: int = 0,
):
    """
    Download SARIF analysis files from docker container and save them to the specified directory.

    Args:
        container_id (str): Docker container ID or name
        output_dir (str): Directory to save analysis results (default: "analysis_results")

    Returns:
        bool: True if successful, False otherwise
    """
    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Download sarif_analysis.json from docker container
    client = docker.from_env()

    try:
        container = client.containers.get(container_id)
    except docker.errors.NotFound:
        print(
            f"Error: Container '{container_id}' not found. Please make sure the container is running."
        )
        return False
    except docker.errors.APIError as e:
        print(f"Error accessing Docker API: {e}")
        return False

    for i in range(30):
        time.sleep(30)
        try:
            exit_code, output = container.exec_run(
                cmd=f"bash -c 'ls /app/sarif_*.json'"
            )

            if exit_code == 0:
                results = output.decode("utf-8").split("\n")
                saved_files = []

                for result_file in results:
                    if result_file:
                        exit_code2, output2 = container.exec_run(
                            cmd=f"cat {result_file}"
                        )

                        if exit_code2 == 0:
                            # Save file with timestamp
                            timestamp = time.strftime("%Y%m%d_%H%M%S")
                            filename = f"{result_file.split('/')[-1].replace('.json', '')}_{project_name}_{timestamp}.json"
                            output_file = output_path / filename

                            with open(output_file, "w", encoding="utf-8") as f:
                                f.write(output2.decode("utf-8"))
                            saved_files.append(str(output_file))

                            print(f"Saved analysis result to: {output_file}")
                        else:
                            print(
                                f"Failed to read file {result_file} (exit code: {exit_code2})"
                            )

                if saved_files:
                    print(f"Successfully saved {len(saved_files)} analysis files:")
                    for file in saved_files:
                        print(f"  - {file}")
                    break
                else:
                    print("No valid analysis files found")
            else:
                print(
                    f"Waiting for SARIF analysis files (ls exit code: {exit_code}). {i*30} seconds elapsed"
                )

        except docker.errors.APIError as e:
            print(
                f"Error executing command in container: {e}. Retrying... {i*30} seconds elapsed"
            )
        except Exception as e:
            print(f"Unexpected error: {e}. Retrying... {i*30} seconds elapsed")

    else:
        print("Failed to get SARIF analysis files after multiple attempts")
        return False

    if extra_wait > 0:
        time.sleep(extra_wait)

    return True


if __name__ == "__main__":
    # First, create a parser to get project_name for dynamic port detection
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument(
        "--project-name",
        type=str,
        required=True,
        help="Name of the project (used for container identification)",
    )

    # Parse known args to get project_name
    pre_args, remaining_args = pre_parser.parse_known_args()

    # Get the container port dynamically based on project_name
    container_port = get_container_port(pre_args.project_name)
    default_host = f"http://localhost:{container_port}"

    # Now create the main parser with dynamic default host
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s", "--sarif", type=str, required=False, help="Path to SARIF file"
    )
    parser.add_argument(
        "-c", "--crash", type=str, required=False, help="Path to crash log file"
    )
    parser.add_argument(
        "-p", "--patch", type=str, required=False, help="Path to patch file"
    )
    parser.add_argument(
        "--pov-sarif",
        type=str,
        required=False,
        help="Path to PoV-SARIF JSON file",
    )
    parser.add_argument(
        "-H",
        "--host",
        type=str,
        default=default_host,
        required=False,
        help=f"CRS-SARIF server host (default: {default_host})",
    )
    parser.add_argument(
        "-e",
        "--extra-wait",
        type=int,
        default=0,
        required=False,
        help="Extra wait time in seconds",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=str,
        default="analysis_results",
        help="Directory to save analysis results (default: analysis_results)",
    )
    parser.add_argument(
        "--project-name",
        type=str,
        required=True,
        help="Name of the project (used for container identification)",
    )
    args = parser.parse_args()

    # Count how many options are provided
    options_provided = sum(
        [
            args.sarif is not None,
            args.crash is not None,
            args.patch is not None,
            args.pov_sarif is not None,
        ]
    )

    if options_provided > 1:
        print(
            "Error: Only one of --sarif, --crash, --patch, or --pov-sarif should be provided"
        )
        exit(-1)

    if options_provided == 0:
        print(
            "Error: One of --sarif, --crash, --patch, or --pov-sarif must be provided"
        )
        exit(-1)

    if args.sarif:
        metadata = dict()
        with open(args.sarif, "r") as f:
            sarif_data = json.load(f)
        sarif_id = uuid.uuid4()
        sarif_match_request = SARIFMatchRequest(
            metadata=metadata,
            sarif=sarif_data,
            sarif_id=sarif_id,
        )
        request_data = sarif_match_request.model_dump()
        request_data["sarif_id"] = str(request_data["sarif_id"])
        response = requests.post(f"{args.host}/match/sarif/", json=request_data)
        print(response)

        container_name = get_container_name(args.project_name)
        if not _download_sarif_analysis_file(
            container_name, args.project_name, args.output_dir, args.extra_wait
        ):
            exit(-1)

    if args.crash:
        pov_id = uuid.uuid4()
        with open(args.crash, "r") as f:
            crash_log = f.read()

        pov_match_request = POVMatchRequest(
            pov_id=pov_id,
            fuzzer_name="fuzzer_name",
            sanitizer="sanitizer",
            testcase="testcase",
            crash_log=crash_log,
        )
        request_data = pov_match_request.model_dump()
        request_data["pov_id"] = str(request_data["pov_id"])
        response = requests.post(f"{args.host}/match/pov/", json=request_data)
        print(response.json())

    if args.patch:
        patch_id = uuid.uuid4()
        with open(args.patch, "r") as f:
            patch_content = f.read()

        patch_match_request = PatchMatchRequest(
            pov_id=uuid.uuid4(),
            patch_id=uuid.uuid4(),
            diff=patch_content,
        )

        request_data = patch_match_request.model_dump()
        request_data["patch_id"] = str(request_data["patch_id"])
        request_data["pov_id"] = str(request_data["pov_id"])
        response = requests.post(f"{args.host}/match/patch/", json=request_data)
        print(response.json())

    if args.pov_sarif:
        # Read PoV-SARIF JSON file
        with open(args.pov_sarif, "r") as f:
            pov_sarif_data = json.load(f)

        response = requests.post(f"{args.host}/match/pov-sarif/", json=pov_sarif_data)
        print(response.json())
