#### Reference ####
# https://github.com/s3team/Squirrel

#### Targets ####
# sqlite3
# postgresql
# mysql
# mariadb

#!/usr/bin/env python3

import yaml
import os
from pathlib import Path
import subprocess
import random
import time

cp_name = os.environ.get("CP_NAME", "")
oss_fuzz_path = Path("/oss-fuzz")
build_path = Path("/out")
src_path = Path("/src")
cores = list(os.environ.get("CORES", "0").split(","))
target_name = os.environ.get("TARGET_NAME", "")

if not cp_name:
    print("CP_NAME is not set")
    exit(-1)

project_aixcc_yaml = Path(f"/oss-fuzz/projects/{cp_name}/.aixcc/config.yaml")

if not project_aixcc_yaml.exists():
    print(f"Project {cp_name} does not exist")
    exit(-1)

with open(project_aixcc_yaml, "r") as f:
    config = yaml.safe_load(f)

if "harness_files" not in config:
    print(f"Harness files not found in .aixcc/config.yaml")
    exit(-1)

harnesses = list(set([h["name"] for h in config.get("harness_files")]))

print(f"Harnesses: {harnesses}")
print("Randomly select harnesses to run")

# choose core_num harnesses
harness_list = []
if len(cores) < len(harnesses):
    harness_list = random.sample(harnesses, len(cores))
else:
    harness_list = harnesses.copy()
    harness_list += random.choices(harnesses, k=len(cores) - len(harnesses))
  
print(f"Selected harnesses: {harness_list}")

sessions = []
for idx, harness in enumerate(harness_list):
    sessions.append(subprocess.Popen(f"taskset -c {cores[idx]} /root/data/run.sh {harness} {target_name} {cores[idx]}", env=os.environ, shell=True))
    
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    for session in sessions:
        session.kill()
