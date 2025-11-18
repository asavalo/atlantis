import argparse
import json
import tarfile
import time
import uuid

import docker
import docker.errors
import requests

from crs_sarif.models.models import (
    PatchMatchRequest,
    POVMatchRequest,
    SARIFMatchRequest,
)


def _download_sarif_analysis_file(container_id: str):
    # Download sarif_analysis.json from docker container
    client = docker.from_env()
    container = client.containers.get(container_id)
    for i in range(30):
        time.sleep(1)
        try:
            exit_code, output = container.exec_run(
                cmd=f"bash -c 'ls /app/sarif_*.json'"
            )

            if exit_code == 0:
                results = output.decode("utf-8").split("\n")
                for result_file in results:
                    if result_file:
                        exit_code2, output2 = container.exec_run(
                            cmd=f"cat {result_file}"
                        )
                        with open(
                            f"{result_file.split('/')[-1]}", "w", encoding="utf-8"
                        ) as f:
                            f.write(output2.decode("utf-8"))

                results = [res.split("/")[-1] for res in results]

                print(f"Successfully retrieved {','.join(results)} using exec_run")
                break
            else:
                print(
                    f"Waiting for sarif analysis file (cat exit code: {exit_code}). {i} seconds elapsed"
                )

        except docker.errors.APIError as e:
            print(
                f"Error executing command in container: {e}. Retrying... {i} seconds elapsed"
            )

    else:
        print("Failed to get sarif analysis file after multiple attempts")
        exit(-1)


if __name__ == "__main__":
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
        "-H",
        "--host",
        type=str,
        default="http://localhost:4321",
        required=False,
        help="CRS-SARIF server host",
    )
    args = parser.parse_args()

    if args.sarif is not None and args.crash is not None and args.patch is not None:
        print(
            "Error: Only one of --sarif, --crash or --patch should be provided, not both"
        )
        exit(-1)

    if args.sarif is None and args.crash is None and args.patch is None:
        print("Error: Either --sarif, --crash or --patch must be provided")
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

        _download_sarif_analysis_file("crs-sarif")

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
