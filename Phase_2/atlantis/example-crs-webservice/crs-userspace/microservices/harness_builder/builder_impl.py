import logging
import os
from pathlib import Path
from typing import Optional
import shlex
import shutil
import sys
import tempfile
import re
import subprocess
import json

import yaml
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from libCRS.challenge import CP
from libCRS.util import run_cmd
from libCRS.util import cp as copy
from libCRS.ossfuzz_lib import get_harness_names
from libatlantis.constants import KAFKA_SERVER_ADDR, FILE_OPS_TOPIC, SHARED_CRS_DIR
from libatlantis.protobuf import FileWrite, ExtractTar, FileOps
from libmsa.kafka import Producer

from .config_gen import create_conf
from . import config

HARNESS_BUILDER_ROOT = Path(__file__).parent
HELPER_SITECUSTOMIZE_CP_SRC_MOUNT_PATH_STRING = b'CP_SRC_MOUNT_PATH '  # intentional trailing space

ADDRESS_SANITIZER_FLAGS = "-fsanitize=address -fsanitize-address-use-after-scope"
UNDEFINED_SANITIZER_FLAGS = "-fsanitize=array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr"
MEMORY_SANITIZER_FLAGS = "-fsanitize=memory -fsanitize-memory-track-origins"
SAN_TO_FLAGS = {
    # "address": ADDRESS_SANITIZER_FLAGS, # intentional, do not build with ASAN for combo'd sans
    "memory": MEMORY_SANITIZER_FLAGS,
    "undefined": UNDEFINED_SANITIZER_FLAGS,
}

logger = logging.getLogger(__name__)

# ripped from infra/helper.py
WORKDIR_REGEX = re.compile(r'\s*WORKDIR\s*([^\s]+)')

def workdir_from_oss_fuzz(oss_fuzz_path: Path, cp_name: str):
    """Gets the WORKDIR from the given lines."""
    default = (Path("/src") / Path(cp_name).name).as_posix()
    oss_fuzz_project_path = oss_fuzz_path / "projects" / cp_name
    dockerfile_path = oss_fuzz_project_path / "Dockerfile"
    lines = dockerfile_path.read_text().splitlines()

    for line in reversed(lines):  # reversed to get last WORKDIR.
        match = re.match(WORKDIR_REGEX, line)
        if match:
            workdir = match.group(1)
            workdir = workdir.replace('$SRC', '/src')

            if not os.path.isabs(workdir):
                workdir = os.path.join('/src', workdir)

            # just pray that default works
            ret = os.path.normpath(workdir)
            return ret if ret != "/src" else default

    return default

def local_to_host_path(path: Path) -> Path:
    """
    Assuming we may be running in a Docker container, use the
    CRS_DOCKER_MOUNTS environment variable, if available, to try to map
    this local/guest path to the true path on the host system.
    If that can't be done, just return the original path.
    """
    crs_docker_mounts = os.environ.get('CRS_DOCKER_MOUNTS')
    if crs_docker_mounts is not None:
        pairs = [x.split(':') for x in crs_docker_mounts.split(';')]
        for host, guest in pairs:
            guest = Path(guest)
            if path == guest:
                return host
            elif guest in path.parents:
                return Path(host) / path.relative_to(guest)

    return path

def untar_artifact(work_dir: Path, tarball: str):
    subprocess.run([
        "tar",
        "xf",
        str(work_dir / tarball),
        "--directory",
        str(work_dir),
    ], check=True)
            

# NOTE may raise exception, please handle
def get_project_yaml_sanitizers(cp_proj_path) -> list[str]:
    project_yaml_path = cp_proj_path / "project.yaml"
    project_yaml_text = project_yaml_path.read_text()
    project_yaml = yaml.load(project_yaml_text, Loader=Loader)
    return project_yaml["sanitizers"]
    
class BuilderImpl:
    def __init__(self, artifacts_path: Path, storage_path: Path, harness_share_path: Path):
        self.artifacts_path = artifacts_path
        self.storage_path = storage_path
        self.harness_share_path = harness_share_path

    @staticmethod
    def mode_to_artifacts(mode: str) -> list[str]:
        if mode in {"libfuzzer", "honggfuzz", "config_gen", "ubsan", "msan", "sans", "optimized"}:
            return []
        elif mode in {"libafl", "libfuzzer_sbcc"}:
            return ["cc_wrapper", "cxx_wrapper", "libfuzzer.so"]
        elif mode == "afl":
            return ["aflplusplus.tar.gz"]
        elif mode == "custom":
            raise NotImplementedError("Custom mode not implemented")
        elif mode in {"symcc", "symcc_clang_cov"}:
            return [
                "cc_wrapper",
                "cxx_wrapper",
                "libsymcc-rt.so",
                "concolicd",
            ]
        elif mode in {"single_input", "single_input_sbcc"}:
            return ["cc_wrapper", "cxx_wrapper", "libpseudofuzzer.so"]
        elif mode == "directed":
            return ["directed_build_deps.tar.gz"]
        else:
            raise ValueError(f"unknown mode: {mode}")

    # def build_llvm_pass(self, cp: CP, llvm_pass_path: Path) -> None:
    #     llvm_pass_name = llvm_pass_path.name
    #     dst_dir = cp.base / "work" / llvm_pass_name
    #     if not dst_dir.exists():
    #         shutil.copytree(llvm_pass_path, dst_dir, dirs_exist_ok=True)
    #     cp.add_env_docker(
    #         {
    #             "CC": "clang",
    #             "CXX": "clang++",
    #         },
    #         overwrite=True,
    #     )
    #     # compiler pass must have a build.sh script at the root
    #     self.execute_runsh_command(
    #         cp, "custom", [str("/" / dst_dir.relative_to(cp.base) / "build.sh")]
    #     )

    @staticmethod
    def create_atlantis_cc_wrappers(
        mode: str, project_work_dir: Path, libfuzzer_path_guest: Path | None = None
    ) -> tuple[Path, Path]:
        cc_wrapper_path = project_work_dir / f"cc_wrapper_{mode}"
        cxx_wrapper_path = project_work_dir / f"cxx_wrapper_{mode}"

        env_vars_text = f"ATLANTIS_CC_INSTRUMENTATION_MODE={mode} "
        if libfuzzer_path_guest is not None:
            env_vars_text += f"LIBFUZZER_PATH={libfuzzer_path_guest} "

        with cc_wrapper_path.open("w") as f:
            f.write(f'#!/bin/bash\n{env_vars_text}/work/cc_wrapper "$@"')
        with cxx_wrapper_path.open("w") as f:
            f.write(f'#!/bin/bash\n{env_vars_text}/work/cxx_wrapper "$@"')

        os.chmod(cc_wrapper_path, 0o755)
        os.chmod(cxx_wrapper_path, 0o755)

        return (
            Path("/work") / cc_wrapper_path.relative_to(project_work_dir),
            Path("/work") / cxx_wrapper_path.relative_to(project_work_dir),
        )

    @staticmethod
    def extract_cp_mount_path(helper_output: bytes) -> str | None:
        needle = HELPER_SITECUSTOMIZE_CP_SRC_MOUNT_PATH_STRING
        needle_idx = helper_output.find(needle)
        if needle_idx == -1:
            return None
        else:
            path_start = needle_idx + len(needle)
            path_end = helper_output.find(b'\n', path_start)
            path = helper_output[path_start : path_end]
            return path.decode('utf-8')

    @staticmethod
    def construct_env_var_args(guest_env_vars: Optional[dict[str, str]]) -> list[str]:
        env_var_args = []
        if guest_env_vars:
            for k, v in guest_env_vars.items():
                env_var_args.append("-e")
                env_var_args.append(f"{k}={v}")
        return env_var_args

    def run_custom_command(
        self,
        cmd: list[str],
        oss_fuzz_path: Path,
        cp_name: str,
        language: str,
        cp_src_path: Path,
        out_dir: Path,
        work_dir: Path,
        guest_env_vars: dict[str, str] | None,
    ):
        project_dir = workdir_from_oss_fuzz(oss_fuzz_path, cp_name)
        sanitizer = os.environ.get("SANITIZER", "address")
        guest_env_vars["SANITIZER"] = sanitizer
        guest_env_vars["ARCHITECTURE"] = "x86_64"
        guest_env_vars["PROJECT_NAME"] = cp_name
        guest_env_vars["HELPER"] = "True"
        env_var_args = self.construct_env_var_args(guest_env_vars)
        full_cmd = [
            '/usr/local/bin/docker',
            'run',
            '--privileged',
            '--shm-size=2g',
            '--platform',
            'linux/amd64',
            '--rm',
            *env_var_args,
            '-v', f'{cp_src_path}:{project_dir}',
            '-v', f'{str(out_dir)}:/out',
            '-v', f'{str(work_dir)}:/work',
            '-t', f'aixcc-afc/{cp_name}',
            *cmd
        ] 
        res = subprocess.run(full_cmd, env=guest_env_vars, capture_output=True)

        if res.returncode == 0:
            msg = f"Ran command: {shlex.join(full_cmd)}"
            logger.info(msg)
            logger.debug(res.stdout.decode(errors="replace"))
            logger.debug(res.stderr.decode(errors="replace"))
        else:
            msg = f"Failed to run command: {shlex.join(full_cmd)}"
            logger.error(msg)
            logger.error(res.stdout.decode(errors="replace"))
            logger.error(res.stderr.decode(errors="replace"))
            return None
        return project_dir
        
        
    def __run_infra_helper_py_command(
        self,
        oss_fuzz_path: Path,
        cp_name: str,
        cp_src_path: Path,
        out_dir: Path,
        work_dir: Path,
        helper_command: list[str],
    ) -> str | None:

        helper_py = oss_fuzz_path / "infra/helper.py"
        helper_sitecustomize = HARNESS_BUILDER_ROOT / "helper_sitecustomize.py"

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)

            (temp_dir / "sitecustomize.py").symlink_to(helper_sitecustomize.resolve())

            pythonpath_var = str(temp_dir)
            host_pythonpath = os.environ.get("PYTHONPATH")
            if host_pythonpath is not None:
                pythonpath_var += ":" + host_pythonpath

            #host_cp_src_path = str(local_to_host_path(cp_src_path))
            host_env = os.environ | {
                "ATLANTIS_OSSFUZZ_DOCKER_MOUNT_SRC": str(cp_src_path),
                "ATLANTIS_OSSFUZZ_DOCKER_MOUNT_OUT": str(out_dir),
                "ATLANTIS_OSSFUZZ_DOCKER_MOUNT_WORK": str(work_dir),
                'PYTHONPATH': pythonpath_var,
            }

            cmd = [
                sys.executable,
                str(helper_py),
                *helper_command,
            ]
            res = run_cmd(cmd, env=host_env)

            cp_mount_path = self.extract_cp_mount_path(res.stdout)

            if res.returncode == 0:
                msg = f"Ran command: {shlex.join(cmd)}"
                logger.debug(msg)
                logger.debug(res.stdout.decode(errors="replace"))
                logger.debug(res.stderr.decode(errors="replace"))
            else:
                msg = f"Failed to run command: {shlex.join(cmd)}"
                logger.error(msg)
                logger.error(res.stdout.decode(errors="replace"))
                logger.error(res.stderr.decode(errors="replace"))
                #raise Exception(msg)
                return None

            return cp_mount_path

    def run_infra_helper_py_build_fuzzers(
        self,
        oss_fuzz_path: Path,
        cp_name: str,
        cp_src_path: Path,
        out_dir: Path,
        work_dir: Path,
        engine: str | None,
        sanitizer: str | None,
        guest_env_vars: dict[str, str] | None,
    ) -> str | None:

        env_var_args = self.construct_env_var_args(guest_env_vars)

        engine_args = ["--engine", engine] if engine else []
        sanitizer_args = ["--sanitizer", sanitizer] if sanitizer else []
        return self.__run_infra_helper_py_command(
            oss_fuzz_path,
            cp_name,
            cp_src_path,
            out_dir,
            work_dir,
            [
                "build_fuzzers",
                *engine_args,
                *sanitizer_args,
                cp_name,
                str(cp_src_path),
                *env_var_args,
            ],
        )

    def run_infra_helper_py_build_image(
        self,
        oss_fuzz_path: Path,
        cp_name: str,
        cp_src_path: Path,
        out_dir: Path,
        work_dir: Path,
    ) -> str | None:
        # check if we need to rebuild
        result = subprocess.run(["/usr/local/bin/docker", "image", "ls"], capture_output=True, check=True, text=True)
        if "aixcc-afc" in result.stdout:
            return
        return self.__run_infra_helper_py_command(
            oss_fuzz_path,
            cp_name,
            cp_src_path,
            out_dir,
            work_dir,
            [
                "build_image",
                "--no-pull",
                cp_name,
            ],
        )


    @staticmethod
    def is_oss_fuzz_harness(harness_path: Path) -> bool:
        return os.access(harness_path, os.X_OK) and (
            harness_path.name not in ["llvm-symbolizer"]
        )

    def build(
        self,
        oss_fuzz_path: Path,
        cp_name: str,
        cp_src_path: Path,
        build_nonce: str,
        mode: str,
        aux: str | None = None
    ) -> tuple[dict[str, str], str | None]:
        cp_proj_path = oss_fuzz_path / "projects" / cp_name
        work_dir = self.storage_path / (build_nonce + "_work")
        out_dir = self.storage_path / (build_nonce + "_out")

        work_dir.mkdir(exist_ok=True)
        out_dir.mkdir(exist_ok=True)

        for artifact in self.mode_to_artifacts(mode):
            artifact_path = self.artifacts_path / artifact
            if artifact_path.is_file():
                shutil.copy(artifact_path, work_dir)
            elif artifact_path.is_dir():
                shutil.copytree(artifact_path, work_dir / artifact, symlinks=True)

        # if mode == "custom":
        #     self.build_llvm_pass(cp, Path(aux))
        # elif mode == "symcc" or mode == "symcc_clang_cov":
        #     self.build_llvm_pass(cp, self.artifacts_path / "symcc-pass")

        if mode in {"single_input", "single_input_sbcc"}:
            libfuzzer_path_guest = Path("/work/libpseudofuzzer.so")
        else:
            libfuzzer_path_guest = None

        if mode in {"libfuzzer", "directed", "afl", "honggfuzz", "config_gen", "ubsan", "msan", "sans", "optimized"}:
            wrapper_cc_guest_path = wrapper_cxx_guest_path = None
        else:
            wrapper_cc_guest_path, wrapper_cxx_guest_path = \
                self.create_atlantis_cc_wrappers(mode, work_dir, libfuzzer_path_guest)

        # Some OSSF projects, such as libpng, require their source
        # directory to be writable -- so we need to make a copy.
        # In addition -- in case we're running in Docker and
        # helper.py will be using the host Docker) -- it needs to be
        # in a host-accessible location, so we can't put it in
        # temp_dir.
        copied_src_path = self.storage_path / (build_nonce + "_src")
        shutil.copytree(cp_src_path, copied_src_path)

        # get language
        project_yaml = cp_proj_path / "project.yaml"
        project_text = project_yaml.read_text()
        project_obj = yaml.load(project_text, Loader=Loader)
        language = project_obj["language"]
        
        guest_env_vars = {
            "FUZZING_LANGUAGE": language,
            "BUILDER_UID": str(os.getuid()),
        }
        if wrapper_cc_guest_path is not None:
            guest_env_vars["CC"] = str(wrapper_cc_guest_path)
        if wrapper_cxx_guest_path is not None:
            guest_env_vars["CXX"] = str(wrapper_cxx_guest_path)

        if mode == "optimized":
            # cflags =  "-O3 -flto -ffat-lto-objects -ffunction-sections -fdata-sections -fno-ident -fmerge-all-constants"
            # guest_env_vars["CFLAGS"] = cflags
            # guest_env_vars["CXXFLAGS"] = cflags
            # guest_env_vars["LDFLAGS"] = "-flto -lm -lpthread -lrt -ldl -lresolv -Wl,--no-as-needed -Wl,--gc-sections -Wl,--build-id=none -Wl,--icf=all -Wl,--hash-style=sysv"

            # more conservative ones, in case of failure
            cflags =  "-O3 -flto -ffat-lto-objects"
            guest_env_vars["CFLAGS"] = cflags
            guest_env_vars["CXXFLAGS"] = cflags
            guest_env_vars["LDFLAGS"] = "-flto -lm -lpthread -lrt -ldl -lresolv -Wl,--no-as-needed"

            guest_env_vars["COVERAGE_FLAGS_none"] = ""
            
        # bypass the conventional logic
        if mode == "directed":
            # check config.yaml generated by libfuzzer mode
            conf_path = cp_proj_path / ".aixcc/config.yaml"
            conf_text = conf_path.read_text()
            conf_obj = yaml.load(conf_text, Loader=Loader)
            harnesses = []
            for conf_line in conf_obj["harness_files"]:
                harnesses.append(conf_line["name"])

            # build image
            self.run_infra_helper_py_build_image(
                oss_fuzz_path, cp_name, copied_src_path, out_dir, work_dir
            )

            # untar artifacts
            untar_artifact(work_dir, "directed_build_deps.tar.gz")
            
            # NOTE keep these wrapper scripts in artifacts, no need to dynamically create them
            guest_cmd = ["/work/directed_build_deps/custom_compile.sh"]
            harness_paths = [f"/out/{harness}" for harness in harnesses] # hopium this is consistent
            guest_cmd.extend(harness_paths)
            cp_mount_path = self.run_custom_command(
                guest_cmd, oss_fuzz_path, cp_name, language, copied_src_path, out_dir, work_dir, guest_env_vars
            )
        elif mode == "afl":
            # build image
            self.run_infra_helper_py_build_image(
                oss_fuzz_path, cp_name, copied_src_path, out_dir, work_dir
            )

            # untar artifacts
            untar_artifact(work_dir, "aflplusplus.tar.gz")

            guest_cmd = ["/work/aflplusplus/custom_compile.sh"]
            guest_env_vars["FUZZING_ENGINE"] = "afl"
            cp_mount_path = self.run_custom_command(
                guest_cmd, oss_fuzz_path, cp_name, language, copied_src_path, out_dir, work_dir, guest_env_vars
            )
        elif mode == "config_gen":
            config_gen_module = Path("/harness_builder/config_gen")
            shutil.copytree(config_gen_module, work_dir / "config_gen")

            # build image
            self.run_infra_helper_py_build_image(
                oss_fuzz_path, cp_name, copied_src_path, out_dir, work_dir
            )

            # custom compile with config_gen bb
            guest_cmd = ["/work/config_gen/bb.py"]
            cp_mount_path = self.run_custom_command(
                guest_cmd, oss_fuzz_path, cp_name, language, copied_src_path, out_dir, work_dir, guest_env_vars
            )
        else:
            # NOTE this is happy as long as infra/constants.py DEFAULT_ENGINE is still libfuzzer
            engine = None
            sanitizer = None
            if mode in {"afl", "honggfuzz"}:
                engine = mode

            if mode == "ubsan":
                sanitizer = "undefined"
            elif mode == "msan":
                sanitizer = "memory"
            elif mode == "sans":
                sanitizer = None
            else:
                sanitizer = "address"

            go_ahead = True

            try:
                sanitizers = get_project_yaml_sanitizers(cp_proj_path)
                if mode == "sans":
                    flags_to_join = [
                        SAN_TO_FLAGS[sanitizer]
                        for sanitizer in sanitizers
                        if sanitizer in SAN_TO_FLAGS
                    ]
                    guest_env_vars["SANITIZER_FLAGS"] = ' '.join(flags_to_join)
                elif sanitizer == "undefined":
                    go_ahead = sanitizer in sanitizers
                elif sanitizer == "memory":
                    go_ahead = sanitizer in sanitizers
                    if "undefined" in sanitizers:
                        logging.info("found ubsan, so skipping msan")
                        go_ahead = False
            except:
                logging.info("project.yaml parsing error, skipping")
                go_ahead = False

            if mode == "optimized":
                sanitizer = "none"

            if go_ahead:
                cp_mount_path = self.run_infra_helper_py_build_fuzzers(
                    oss_fuzz_path, cp_name, copied_src_path, out_dir, work_dir, engine,
                    sanitizer=sanitizer, guest_env_vars=guest_env_vars
                )
            else:
                cp_mount_path = None

        # Setup harness share path
        harness_share_out_dir = self.harness_share_path / (build_nonce + "_out")
        harness_share_out_dir.mkdir(exist_ok=True, parents=True)

        if cp_mount_path is None:
            # Mark build as failed
            failed_file = harness_share_out_dir / "FAILED"
            failed_file.touch()
            return {}, None

        # if this is the stupid mount
        if "local-source-mount" in cp_mount_path:
            cp_mount_path = workdir_from_oss_fuzz(oss_fuzz_path, cp_name)

        # get harness names from build
        harness_names = get_harness_names(out_dir)

        # create .aixcc/config.yaml
        if mode == "config_gen":
            write_ops = []
            extract_ops = []
            conf_path = cp_proj_path / ".aixcc/config.yaml"
            tmp_conf_path = cp_proj_path / ".aixcc/config.yaml.tmp"

            # copy config.yaml to config.yaml.tmp
            if conf_path.exists():
                original_conf = conf_path.read_bytes()
                write_ops.append(FileWrite(
                    file_path=str(tmp_conf_path),
                    content=original_conf,
                ))

            config_json_path = work_dir / "config.json"
            conf = {"harness_files": []}
            with config_json_path.open("r") as f:
                config_json = json.load(f)
                for harness in config_json:
                    conf["harness_files"].append({"name": harness, "path": config_json[harness]})

            # move tarball from work directory to shared crs fs
            tarball_path = work_dir / "project.tar.gz"
            shared_tarball_path = config.HARNESS_SHARE_DIR / "project.tar.gz"
            oss_fuzz_path = Path(os.environ.get('CRS_OSS_FUZZ_PATH', "/oss_fuzz"))

            destination = oss_fuzz_path / "atlantis"
            shutil.move(tarball_path, shared_tarball_path)
            extract_ops.append(ExtractTar(
                tarball=str(shared_tarball_path),
                destination=str(destination),
            ))
                    
            # write to new config.yaml
            conf_str = yaml.dump(conf)
            write_ops.append(FileWrite(
                file_path=str(conf_path),
                content=conf_str.encode('utf-8'),
            ))

            # send messages
            producer = Producer(KAFKA_SERVER_ADDR, FILE_OPS_TOPIC)
            producer.send_message(FileOps(writes=write_ops, extractions=extract_ops))

        # copy harnesses to harness_share_path
        harnesses: dict[str, str] = {}
        # Don't screen the harnesses in harness builder, screen it in controller
        for harness_id in harness_names:
            harness_path = out_dir / harness_id
            shared_harness_path = harness_share_out_dir / harness_id
            copy(out_dir, harness_share_out_dir)
            harnesses[harness_id] = str(shared_harness_path.resolve())
            #if harness_id == desired_harness:
                #return {desired_harness: harnesses[harness_id]}, cp_mount_path

        return harnesses, cp_mount_path
