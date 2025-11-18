import argparse
import uuid
from pathlib import Path

import requests
from python_aixcc_challenge.detection.models import AIxCCChallengeProjectDetection


def request_detection_patch(detection_yaml_path: Path):
    detection_yaml = AIxCCChallengeProjectDetection.from_toml(detection_yaml_path)
    pov_id = args.pov_id or str(uuid.uuid4())
    response = requests.post(
        f"http://{args.target}/v1/patch/",
        json={
            "project_name": detection_yaml.project_name,
            "blobs": [
                {
                    "blob_data": detection_yaml.blobs[0].blob,
                    "sanitizer_name": detection_yaml.blobs[0].sanitizer_name,
                    "harness_name": detection_yaml.blobs[0].harness_name,
                }
            ],
            "pov_id": pov_id,
            "type": detection_yaml.mode.type,
        },
    )
    print(response.status_code)
    print(response.text)


parser = argparse.ArgumentParser()
parser.add_argument("detection_file", type=Path)
parser.add_argument("--target", type=str, default="localhost:8000")
parser.add_argument("--pov-id", type=str, default=None)

args = parser.parse_args()

if __name__ == "__main__":
    request_detection_patch(args.detection_file)
