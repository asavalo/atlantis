#!/usr/bin/env python3

import yaml
import subprocess
from pathlib import Path
import argparse
import uuid
from loguru import logger
import os

env_cp_name = os.environ.get("CP_NAME", "")
env_target_name = os.environ.get("TARGET_NAME", "")
collect_results = os.environ.get("COLLECT_RESULTS", "false").lower() == "true"
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

root_dir = Path(os.environ.get("USERSPACE_CUSTOM_FUZZERS_REPO_PATH", str(Path(__file__).parent.parent)))
fuzzers_yaml = root_dir / "fuzzers.yaml"
with open(fuzzers_yaml, "r") as f:
    fuzzers = yaml.safe_load(f)


def get_config(fuzzer: str):
    def load_config(category: str):
        with open(root_dir / category / "config.yaml", "r") as f:
            config = yaml.safe_load(f)
        return config

    for category in fuzzers:
        for f in fuzzers[category]["fuzzers"]:
            if fuzzer == f:
                return load_config(category)[f]
    return None


def get_container_name(fuzzer: str):
    container_name = f"custom-fuzzer-{fuzzer}-{uuid.uuid4().hex[:8]}"
    subprocess.run(f"docker rm -f {container_name} > /dev/null 2>&1", shell=True)
    return container_name


def start_container(
    fuzzer: str,
    target_src_path: Path,
    work_dir: Path,
    oss_fuzz_path: Path,
    build_dir: Path,
    cores: list[int] = [0],
    cp_name: str = env_cp_name,
    target_name: str = env_target_name,
    container_name: str = None,
):
    config = get_config(fuzzer)
    if config is None:
        logger.error(f"Fuzzer {fuzzer} not found")
        exit(-1)

    guest_src_path = config["src_path"]
    host_src_path = target_src_path
    guest_corpus_path = config["corpus_path"]
    host_corpus_path = work_dir / "corpus"
    guest_crashes_path = config["crashes_path"]
    host_crashes_path = work_dir / "crashes"
    host_oss_fuzz_path = oss_fuzz_path
    guest_oss_fuzz_path = config["oss_fuzz_path"]
    host_build_path = build_dir
    guest_build_path = config["build_path"]
    if container_name is None:
        container_name = get_container_name(fuzzer)
    cmd = f"docker run -dit --privileged --init --name {container_name}"
    # cmd += f" -u root" # just bypass permission issues
    cmd += f" -v {host_src_path}:{guest_src_path}"
    cmd += f" -v {host_corpus_path}:{guest_corpus_path}"
    cmd += f" -v {host_crashes_path}:{guest_crashes_path}"
    cmd += f" -v {host_oss_fuzz_path}:{guest_oss_fuzz_path}"
    cmd += f" -v {host_build_path}:{guest_build_path}"
    if len(cores) > 0:
        cmd += f" --cpuset-cpus={','.join([str(c) for c in cores])}"
    for env_var in config["env_vars"]:
        if env_var == "CORES" and len(cores) > 0:
            cmd += f" -e {env_var}={','.join([str(c) for c in cores])}"
        elif env_var == "CP_NAME":
            cmd += f" -e {env_var}={cp_name}"
        elif env_var == "TARGET_NAME":
            cmd += f" -e {env_var}={target_name}"
    cmd += f" {fuzzer}"
    cmd += " sleep infinity"
    logger.info(f"=== Starting container {container_name} with command: {cmd}")
    subprocess.run(cmd, shell=True, check=True)
    return container_name


def container_exec_cmd(container_name: str, cmd: str, debug: bool = True):
    if debug:
        return f"docker exec -it {container_name} {cmd}"
    else:
        return f"docker exec -i {container_name} {cmd}"


def build_fuzzer(fuzzer: str, container_name: str):
    config = get_config(fuzzer)
    if config is None:
        logger.error(f"Fuzzer {fuzzer} not found")
        return ""

    build_cmd = config["build_cmd"]
    logger.info(f"=== Building fuzzer {fuzzer} with command: {build_cmd}")
    try:
        subprocess.run(
            container_exec_cmd(container_name, build_cmd, debug=False), shell=True, check=True
        )
    except Exception as e:
        logger.error(f"Error: {e}")
        return ""
    return container_name


def run_fuzzer(fuzzer: str, container_name: str, debug: bool = True):
    config = get_config(fuzzer)
    if config is None:
        logger.error(f"Fuzzer {fuzzer} not found")
        return None, ""

    fuzz_cmd = config["fuzz_cmd"]
    logger.info(f"=== Running fuzzer {fuzzer} with command: {fuzz_cmd}")
    handle = None
    try:
        if debug:
            subprocess.run(container_exec_cmd(container_name, fuzz_cmd, debug), shell=True, check=True)
        else:
            handle = subprocess.Popen(container_exec_cmd(container_name, fuzz_cmd, debug), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        logger.error(f"Error: {e}")
        return None, ""
    return handle, container_name


def stop_container(container_name: str):
    subprocess.run(["docker", "stop", container_name])


def delete_container(container_name: str):
    subprocess.run(["docker", "rm", "-f", container_name])


def collect_run_results(container_name: str, work_dir: Path):
    subprocess.run(
        f"sudo chown -R $USER:$USER {work_dir}",
        shell=True,
        cwd=root_dir,
    )
    subprocess.run(
        [
            f"tar -cf - -C {work_dir} . | zstd -19 -T0 -o {container_name}_results.tar.zst"
        ],
        shell=True,
        cwd=root_dir,
    )


def main():
    # arg parser
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", type=str, default=str(root_dir / "scratch/src"))
    parser.add_argument("--fuzzer", type=str, required=True)
    parser.add_argument(
        "--work-dir", type=str, default=str(root_dir / "scratch/workdir")
    )
    parser.add_argument(
        "--oss-fuzz", type=str, default=str(root_dir / "scratch/oss-fuzz")
    )
    parser.add_argument(
        "--build-dir", type=str, default=str(root_dir / "scratch/oss-fuzz/build/out")
    )
    parser.add_argument("--cores", type=str, default="")
    args = parser.parse_args()

    # run fuzzer
    work_dir = Path(args.work_dir)
    target_src_path = Path(args.src)
    oss_fuzz_path = Path(args.oss_fuzz)
    build_dir = Path(args.build_dir)
    cores = [int(c) for c in args.cores.split(",")]
    if not target_src_path.exists():
        logger.error(f"Target source path {target_src_path} does not exist")
        exit(-1)
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        container_name = get_container_name(args.fuzzer)
        container_name = start_container(
            args.fuzzer,
            target_src_path,
            work_dir,
            oss_fuzz_path,
            build_dir / env_cp_name,
            cores,
            env_cp_name,
            env_target_name,
            container_name,
        )
        if container_name != build_fuzzer(args.fuzzer, container_name):
            logger.error(f"Failed to build fuzzer {args.fuzzer}")
            exit(-1)
        handle, c_name = run_fuzzer(args.fuzzer, container_name)
        if c_name != container_name:
            logger.error(f"Failed to run fuzzer {args.fuzzer}")
            exit(-1)
    except Exception as e:
        logger.error(f"Error: {e}")
        exit(-1)
    finally:
        stop_container(container_name)
        logger.info(f"=== Stopped container {container_name}")
        if collect_results:
            logger.info(f"=== Collecting run results")
            collect_run_results(container_name, work_dir)


if __name__ == "__main__":
    main()
