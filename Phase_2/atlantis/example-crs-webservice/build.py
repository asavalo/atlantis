#!/usr/bin/env python3

import os
import logging
import coloredlogs
import argparse
import glob
from pathlib import Path

logger = logging.getLogger(__name__)
coloredlogs.install(fmt="%(asctime)s %(levelname)s %(message)s")
CUR_FILE = __file__
CUR_DIR = Path(os.path.dirname(__file__))

CUSTOM_LLM = True


class Module:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.name = base_dir.name

    def __have(self, name):
        return (self.base_dir / name).exists()

    def log(self, msg):
        logging.info(f"[{self.name}] {msg}")

    def run(self, cmd):
        ret = os.system(f"cd {self.base_dir} && {cmd}")
        if ret != 0:
            self.log(f"fail to execute {cmd}")
            exit(-1)
        return ret

    def is_valid_target(self):
        have_build_sh = self.__have("docker-build.sh")
        have_push_sh = self.__have("docker-img-push.sh")
        if have_build_sh or have_push_sh:
            return have_build_sh and have_push_sh
        return self.__have("Dockerfile")

    def build_docker_img(self):
        self.log("Build docker img..")
        if self.__have("docker-build.sh"):
            return self.run("./docker-build.sh")

        if self.__have("Dockerfile"):
            return self.run(f"docker build -t {self.name} .")

    def push_docker_img(self, registry: str, version: str):
        remote = f"{registry}/{self.name}"
        self.log(f"Push {self.name} to {remote}")
        if self.__have("docker-img-push.sh"):
            return self.run(f"./docker-img-push.sh {registry} {version}")

        if self.__have("Dockerfile"):
            cmd = f"docker image tag {self.name} {remote}:{version}"
            cmd += f"&& docker image push {remote}:{version}"
            return self.run(cmd)


def build_one(target: str, registry: str, version: str):
    if target == "":
        return
    target = Module(CUR_DIR / target)
    if not target.is_valid_target():
        logging.error(f"{target.name}: Invalid target, check README")
        return

    target.build_docker_img()
    if registry != "":
        target.push_docker_img(registry, version)


def main_build(args):
    if args.target != "":
        build_one(args.target, args.push, args.version)
    else:
        for subdir in CUR_DIR.iterdir():
            if "crs-p3" in str(subdir) and not CUSTOM_LLM:
                print("SKIP Custom LLM, crs-p3")
                continue
            if subdir.is_dir():
                build_one(subdir.name, args.push, args.version)


if __name__ == "__main__":
    assert os.getenv("GITHUB_PAT") != None
    if CUSTOM_LLM:
        assert os.getenv("P3_HF_TOKEN") != None
    parser = argparse.ArgumentParser(description="Build all docker images and push")
    subparsers = parser.add_subparsers(title="commands", required=True)
    parser_build = subparsers.add_parser("build", help="Build all docker images")
    parser_build.set_defaults(func=main_build)
    parser_build.add_argument("--target", help="target module", default="")
    parser_build.add_argument("--push", help="docker registry", default="")
    parser_build.add_argument(
        "--version", help="docker image version", default="latest"
    )

    args = parser.parse_args()
    args.func(args)
