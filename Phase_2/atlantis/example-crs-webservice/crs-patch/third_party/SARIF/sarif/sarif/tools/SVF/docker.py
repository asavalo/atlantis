import io
import os
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Literal

from docker.models.containers import Container
from loguru import logger

from sarif.context import SarifEnv
from sarif.models import CP
from sarif.utils.docker import OSSFuzzDocker


class SVFDocker(OSSFuzzDocker):
    tool_name: str = "svf"
    build_name: str = ""
    _container_ids = set()

    dockerfile = """
FROM {}

RUN apt-get update -qq
RUN apt-get install -y build-essential make cmake ninja-build git python3 python3-dev python3-pip autoconf libtool libzstd-dev texinfo bison flex pkg-config wget gawk gnupg lsb-release llvm-18
#libc++-18-dev libc++abi-18-dev

ENV LLVM_DIR=/usr/lib/llvm-18/cmake
ENV LLVM_COMPILER=clang
ENV LLVM_CC_NAME=clang
ENV LLVM_CXX_NAME=clang++
ENV LLVM_LINK_NAME=llvm-link-18
ENV CC=clang
ENV CXX=clang++

ENV SVF=/src/SVF

# Upgrade binutils
RUN cd /tmp && \
    wget https://ftp.gnu.org/gnu/binutils/binutils-2.42.tar.gz && \
    tar xvf binutils-2.42.tar.gz && \
    cd binutils-2.42 && \
    mkdir build && \
    cd build && \
    ../configure --prefix=/usr/local && \
    make -j$(nproc) && \
    make install

# Build SVF
COPY deps/SVF $SVF
RUN cd $SVF && bash ./build.sh

# Install GLLVM
RUN cd /tmp && \
    wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz && \
    export PATH=$PATH:/usr/local/go/bin && \
    go install github.com/SRI-CSL/gllvm/cmd/...@latest

ENV SVF_LIB=$SVF/Release-build/lib
ENV SVF_BIN=$SVF/Release-build/bin
ENV Z3_DIR=$SVF/z3.obj
ENV SVF_src=$SVF
ENV SVF_DIR=$SVF
ENV SVF_HEADER=$LLVM_DIR
ENV PATH=/usr/bin:$PATH:/usr/local/go/bin:/root/go/bin:$SVF_BIN
        """

    def __init__(
        self,
        cp: CP,
        *,
        # TODO: add other PTA options
        mode: Literal[
            "ander", "nander", "sander", "sfrander", "steens", "fspta", "vfspta", "type"
        ] = "ander",
        out_dir: Path | None = None,
    ):
        if not (Path(os.getcwd()) / "deps" / "SVF").exists():
            raise ValueError(
                "SVF is not installed. Run this script in the root of the sarif package dir"
            )

        self.out_dir = out_dir

        docker_file_path = Path(os.getcwd()) / "Dockerfile_svf"
        super().__init__(cp, docker_file_path=docker_file_path)

        if self.cp.language == "java":
            raise ValueError("SVF does not support Java")

        self.mode = mode

    def _check_all_bc_extracted(self):
        for harness in self.cp.harnesses:
            harness_path = f"/out/{harness.name}"
            result = self.container.exec_run(f"test -f {harness_path}.bc")
            if result.exit_code == 0:
                logger.debug(
                    f"Harness bc file for {harness.name} already exists at {harness_path}.bc"
                )
                continue
            else:
                logger.debug(
                    f"Harness bc file for {harness.name} does not exist at {harness_path}.bc"
                )
                return False
        return True

    def _start_container(self):
        self._cleanup_existing_containers()

        env = {
            "FUZZING_ENGINE": "libfuzzer",
            "SANITIZER": "address",
            "ARCHITECTURE": "x86_64",
            "PROJECT_NAME": f"aixcc/{self.cp.language}/{self.cp.name}",
            "HELPER": "True",
            "FUZZING_LANGUAGE": self.cp.language,
        }

        if self.out_dir is None:
            svf_out_dir = SarifEnv().out_dir / "SVF"
        else:
            svf_out_dir = self.out_dir

        if not svf_out_dir.exists():
            svf_out_dir.mkdir(parents=True, exist_ok=True)

        container_name = f"svf_{self.cp.language}_{self.cp.name}_{int(time.time())}"

        self.container: Container = self.client.containers.run(
            image=self.image_name,
            command=["/bin/bash"],
            detach=True,
            tty=True,
            stdin_open=True,
            name=container_name,  # Set the container name
            volumes={svf_out_dir.as_posix(): {"bind": "/out", "mode": "rw"}},
            environment=env,
        )

        logger.debug(
            f"Container {self.container.id} started with name {container_name}"
        )

        return self.container

    def _cleanup_existing_containers(self):
        containers = self.client.containers.list(all=True)

        for container in containers:
            if container.name and container.name.startswith(
                f"svf_{self.cp.language}_{self.cp.name}_"
            ):
                try:
                    container.stop()
                    container.remove()
                    logger.debug(
                        f"Cleaned up container {container.id} with name {container.name}"
                    )
                except Exception as e:
                    logger.warning(f"Failed to clean up container {container.id}: {e}")

    def build_cp(self):
        if self._check_all_bc_extracted():
            logger.debug("All bc files already extracted. Skipping build")
            return

        start_time = time.time()

        cmd = "compile"

        env_vars = self.container.exec_run("env").output.decode().strip().split("\n")
        env_dict = {}
        for var in env_vars:
            if "=" in var:
                key, value = var.split("=", 1)
                env_dict[key] = value

        env_dict.update(
            {
                "CC": "gclang",
                "CXX": "gclang++",
                "CFLAGS": env_dict["CFLAGS"].replace("-O1 ", "-O0 "),
                "CXXFLAGS": env_dict["CXXFLAGS"].replace("-O1 ", "-O0 "),
            }
        )

        self._exec(cmd, env=env_dict)

        elapsed_time = time.time() - start_time
        logger.debug(f"Build {self.cp.name} with gclang in {elapsed_time} seconds")

    def extract_bc(self):
        if self._check_all_bc_extracted():
            logger.debug("All bc files already extracted. Skipping extract_bc")
            return

        for harness in self.cp.harnesses:
            logger.debug(f"Extracting .bc file for {harness.name}")

            harness_path = f"/out/{harness.name}"

            # Check if the harness .bc file already exists
            result = self.container.exec_run(f"test -f {harness_path}.bc")
            if result.exit_code == 0:
                logger.debug(
                    f"Harness {harness.name} already exists at {harness_path}.bc"
                )
                continue

            logger.debug(f"Extracting .bc file for {harness.name}")

            cmd = " ".join(
                [
                    "get-bc",
                    harness_path,
                ]
            )

            self._exec(cmd)

            logger.debug(f"Extracted .bc file for {harness.name}")

    def create_callgraph(self):
        start_time = time.time()
        for harness in self.cp.harnesses:
            logger.debug(f"Creating call graph for {harness.name}")

            harness_path = f"/out/{harness.name}"

            # Check if the call graph already exists
            call_graph_path = f"/out/call_graph_{self.mode}_{harness.name}.dot"

            result = self.container.exec_run(f"test -f {call_graph_path}")
            if result.exit_code == 0:
                logger.debug(
                    f"Callgraph for harness {harness.name} already exists at {call_graph_path}. Skipping..."
                )
                continue

            logger.debug(f"Constructing call graph for {harness.name}")

            # wpa -ander -dump-callgraph swap.ll
            # ae  cfl  dvf  llvm2svf  mta  saber  svf-ex  wpa
            cmd = " ".join(
                [
                    "bash -c",
                    f"'/src/SVF/Release-build/bin/wpa -{self.mode} -dump-callgraph {harness_path}.bc && mv callgraph_final.dot {call_graph_path}'",
                ]
            )
            logger.info(f"Running command: {cmd}")
            self._exec(cmd)

            logger.debug(f"add source filenames to {call_graph_path}")

            # Add source filenames to function nodes in the DOT file
            self._add_source_filenames_to_dot(call_graph_path, harness_path)

            logger.debug(f"Call graph created for {harness.name}")

        elapsed_time = time.time() - start_time
        logger.debug(f"Call graph creation completed in {elapsed_time} seconds")

    def _add_source_filenames_to_dot(self, dot_file_path, bc_file_path):
        import re

        check_cmd = "which llvm-dis-18"
        result = self.container.exec_run(check_cmd)
        llvm_dis_cmd = "llvm-dis-18" if result.exit_code == 0 else "llvm-dis"

        output_ll_path = f"{bc_file_path}.ll"
        cmd = f'bash -c "{llvm_dis_cmd} {bc_file_path}.bc -o {output_ll_path}"'

        result = self.container.exec_run(cmd)
        if result.exit_code != 0:
            logger.warning(f"Failed to generate LLVM IR from {bc_file_path}.bc")
            return

        with tempfile.TemporaryDirectory() as temp_dir:
            logger.info(
                f"Extracting LLVM IR from {output_ll_path} to temp dir {temp_dir}"
            )
            stream, stat = self.container.get_archive(output_ll_path)
            file_bytes = b"".join(chunk for chunk in stream)

            with tarfile.open(fileobj=io.BytesIO(file_bytes)) as tar:
                tar.extractall(path=temp_dir)

            extracted_ll_path = os.path.join(temp_dir, os.path.basename(output_ll_path))
            with open(extracted_ll_path, "r") as f:
                lines = f.readlines()

        dbg_to_func = {}
        sub_to_file = {}
        file_map = {}

        for line in lines:
            m = re.search(r"define\s+.*@([^( ]+)\s*\(.*\)\s+.*!dbg !(\d+)", line)
            if m:
                func_name, dbg_id = m.groups()
                dbg_to_func[dbg_id] = func_name

        for line in lines:
            m = re.search(r"!(\d+) = distinct !DISubprogram\(.*file: !(\d+)", line)
            if m:
                dbg_id, file_id = m.groups()
                sub_to_file[dbg_id] = file_id

        for line in lines:
            m = re.search(
                r'!(\d+) = !DIFile\(filename: "([^"]+)", directory: "([^"]+)"', line
            )
            if m:
                file_id, fname, fdir = m.groups()
                file_map[file_id] = os.path.join(fdir, fname)

        func_to_file = {}
        for dbg_id, func_name in dbg_to_func.items():
            file_id = sub_to_file.get(dbg_id)
            file_path = file_map.get(file_id)
            if file_path:
                func_to_file[func_name] = file_path

        if "LLVMFuzzerTestOneInput" in func_to_file:
            logger.info(
                f"LLVMFuzzerTestOneInput: {func_to_file['LLVMFuzzerTestOneInput']}"
            )
        else:
            logger.info("LLVMFuzzerTestOneInput not found")

        # logger.info(f"func_to_file: {func_to_file}")

        cmd = f"cat {dot_file_path}"
        result = self.container.exec_run(cmd)
        if result.exit_code != 0:
            return

        dot_content = result.output.decode()

        def add_file_name_to_node(match):
            label = match.group(0)
            fun_match = re.search(r"{fun: ([^}]+)}", label)
            if fun_match:
                func = fun_match.group(1).replace("\\", "")
                file_name = func_to_file.get(func)
                if file_name:
                    label = label[:-1] + f', file_name="{file_name}"]'
                    return label
            return label

        modified_dot = re.sub(
            r'\[.*?label="[^"]*\{fun: [^}]*\}[^"]*".*?\]',
            add_file_name_to_node,
            dot_content,
        )

        with open("/tmp/modified.dot", "w") as f:
            f.write(modified_dot)

        # Create tar stream in memory
        tarstream = io.BytesIO()
        with tarfile.open(fileobj=tarstream, mode="w") as tar:
            tar.add("/tmp/modified.dot", arcname=os.path.basename(dot_file_path))
        tarstream.seek(0)

        # Send to container
        self.container.put_archive(os.path.dirname(dot_file_path), tarstream)

    def run(self):
        self.build_cp()
        self.extract_bc()
        self.create_callgraph()

        logger.debug("SVF call graph generation completed")

    @classmethod
    def cleanup_all_containers(cls):
        from docker import from_env

        client = from_env()

        for container_id in list(cls._container_ids):
            try:
                container = client.containers.get(container_id)
                container.stop()
                container.remove()
                logger.debug(f"Cleaned up tracked container {container_id}")
            except Exception as e:
                logger.warning(
                    f"Failed to clean up tracked container {container_id}: {e}"
                )
            finally:
                cls._container_ids.discard(container_id)

        containers = client.containers.list(all=True)
        cleaned_count = 0
        for container in containers:
            if container.name and container.name.startswith("svf_"):
                try:
                    container.stop()
                    container.remove()
                    logger.debug(
                        f"Cleaned up container {container.id} with name {container.name}"
                    )
                    cleaned_count += 1
                except Exception as e:
                    logger.warning(f"Failed to clean up container {container.id}: {e}")

        logger.info(f"Cleaned up {cleaned_count} SVF containers")

    @classmethod
    def cleanup_created_containers(cls):
        from docker import from_env

        client = from_env()
        containers = client.containers.list(all=True)

        cleaned_count = 0
        for container in containers:
            if container.status == "Created":
                try:
                    container.remove(force=True)
                    logger.debug(
                        f"Cleaned up container in 'Created' state: {container.id}"
                    )
                    cleaned_count += 1
                except Exception as e:
                    logger.warning(f"Failed to clean up container {container.id}: {e}")

        logger.info(f"Cleaned up {cleaned_count} containers in 'Created' state")

    @classmethod
    def attach_to_container(cls, container_name=None):
        import subprocess
        import sys

        from docker import from_env

        client = from_env()

        if container_name is None:
            containers = client.containers.list(all=True)
            svf_containers = [
                c for c in containers if c.name and c.name.startswith("svf_")
            ]

            if not svf_containers:
                logger.info("No SVF containers found.")
                return

            print("\nAvailable SVF containers:")
            for i, container in enumerate(svf_containers):
                print(
                    f"{i+1}. {container.name} (ID: {container.id}, Status: {container.status})"
                )

            try:
                choice = int(
                    input(
                        "\nEnter the number of the container to attach to (0 to cancel): "
                    )
                )
                if choice == 0:
                    return
                if choice < 1 or choice > len(svf_containers):
                    logger.error("Invalid choice.")
                    return

                container = svf_containers[choice - 1]
            except ValueError:
                logger.error("Invalid input. Please enter a number.")
                return
        else:
            try:
                container = client.containers.get(container_name)
            except Exception as e:
                logger.error(f"Container '{container_name}' not found: {e}")
                return

        if container.status != "running":
            logger.info(f"Container {container.name} is not running. Starting it...")
            try:
                container.start()
                logger.info(f"Container {container.name} started.")
            except Exception as e:
                logger.error(f"Failed to start container: {e}")
                return

        logger.info(f"Attaching to container {container.name} (ID: {container.id})...")
        logger.info("Type 'exit' to leave the container.")

        try:
            subprocess.run(
                ["docker", "exec", "-it", container.id, "/bin/bash"], check=True
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to attach to container: {e}")
        except KeyboardInterrupt:
            logger.info("Detached from container.")
