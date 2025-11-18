#!/usr/bin/env python3

import argparse
from pathlib import Path
import os
from loguru import logger
import subprocess
import sys


root_dir = Path(__file__).parent.parent
oss_fuzz_dir = Path(os.environ.get("OSS_FUZZ_PATH", root_dir / "scratch/oss-fuzz"))
crs_target_src_dir = Path(os.environ.get("CRS_TARGET_SRC_PATH", root_dir / "scratch/src"))
libprotobuf_mutator_dir = root_dir / "lpm/libprotobuf-mutator"

if not oss_fuzz_dir.exists():
  logger.info(f"Since {oss_fuzz_dir} is empty, cloning oss-fuzz-aixcc into {oss_fuzz_dir}")
  subprocess.run(f"git clone git@github.com:aixcc-finals/oss-fuzz-aixcc.git {str(oss_fuzz_dir)}", shell=True)

parser = argparse.ArgumentParser()
parser.add_argument("--fuzzer", type=str, required=True)
parser.add_argument("--target", type=str, required=True)

args = parser.parse_args()

if args.fuzzer == args.target:
  logger.error("Fuzzer and target cannot be the same")
  exit(-1)

# basic idea is to just add this proto based fuzzer into oss-fuzz and run the helper script
# this may cause differences from the original build and fail, but let's ignore that for now
# copy files in lpm/<fuzzer> to oss_fuzz/projects/<fuzzer>
lpm_fuzzer_dir = root_dir / f"lpm/{args.fuzzer}"
oss_fuzz_projects_dir = oss_fuzz_dir / "projects"
logger.info(f"Copying {lpm_fuzzer_dir} into {oss_fuzz_projects_dir}")

if (oss_fuzz_projects_dir / args.fuzzer).exists():
  logger.info("oss-fuzz project for proto fuzzer already exists, removing...")
  subprocess.run(f"rm -rf {str(oss_fuzz_projects_dir / args.fuzzer)}", shell=True)

logger.info(f"Copying files from lpm/{args.fuzzer} to oss_fuzz/projects/{args.fuzzer}")
subprocess.run(f"cp -r {str(lpm_fuzzer_dir)} {str(oss_fuzz_projects_dir)}", shell=True)
subprocess.run(f"cp -r {str(libprotobuf_mutator_dir)} {str(oss_fuzz_projects_dir / args.fuzzer)}", shell=True)

logger.info(f"Copying {crs_target_src_dir} into oss_fuzz/projects/{args.fuzzer}/crs_target_src")
subprocess.run(f"cp -r {str(crs_target_src_dir)} {str(oss_fuzz_projects_dir / args.fuzzer / 'crs_target_src')}", shell=True)
