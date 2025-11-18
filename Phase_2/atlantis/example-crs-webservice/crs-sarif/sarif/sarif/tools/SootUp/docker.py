import io
import os
import tarfile
import tempfile
import time
import shutil
from pathlib import Path
from typing import Literal

from docker.models.containers import Container
from loguru import logger

from sarif.context import SarifEnv
from sarif.models import CP
from sarif.utils.docker import OSSFuzzDocker


class SootupDocker(OSSFuzzDocker):
    tool_name: str = "sootup"
    build_name: str = ""
    _container_ids = set()

    dockerfile = """
FROM {}

ENV SOOTUP_DIR=/opt/sootup
COPY deps/sootup  /opt/sootup
RUN cd /opt/sootup/deps/SootUp && mvn clean install -DskipTests
RUN cd /opt/sootup/ && mvn clean package
WORKDIR /src
CMD ["/bin/bash"]
        """

    def __init__(
        self,
        cp: CP,
        *,
        # TODO: add other PTA options
        mode: Literal[
            "cha", "rta", "pta"
        ] = "cha",
        pta_algorithm: Literal[
            "insens",
            "callsite_sensitive_1",
            "callsite_sensitive_2",
            "object_sensitive_1",
            "object_sensitive_2",
            "type_sensitive_1",
            "type_sensitive_2",
            "hybrid_object_sensitive_1",
            "hybrid_object_sensitive_2",
            "hybrid_type_sensitive_1",
            "hybrid_type_sensitive_2",
            "eagle_object_sensitive_1",
            "eagle_object_sensitive_2",
            "zipper_object_sensitive_1",
            "zipper_object_sensitive_2",
            "zipper_callsite_sensitive_1",
            "zipper_callsite_sensitive_2",
        ] = "insens",
        out_dir: Path | None = None,
    ):
        sootup_src = Path(os.getcwd()).parent / "sootup"
        sootup_dst = Path(os.getcwd()) / "deps" / "sootup"
        logger.info(f"sootup_src: {sootup_src}")
        logger.info(f"sootup_dst: {sootup_dst}")
        if sootup_src.exists():
            if sootup_dst.exists():
                shutil.rmtree(sootup_dst)
            shutil.copytree(sootup_src, sootup_dst)
        
        if not (Path(os.getcwd()) / "deps" / "sootup").exists():
            raise ValueError(
                "SootUp is not installed. Run this script in the root of the sarif package dir"
            )

        self.out_dir = out_dir

        docker_file_path = Path(os.getcwd()) / "Dockerfile_sootup"
        super().__init__(cp, docker_file_path=docker_file_path)

        if self.cp.language == "c" or self.cp.language == "cpp":
            raise ValueError("SootUp does not support C/C++")

        self.mode = mode
        self.pta_algorithm = pta_algorithm
        logger.info(f"SootUp mode: {self.mode}")
        logger.info(f"SootUp pta_algorithm: {self.pta_algorithm}")

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

        logger.info(f"SarifEnv().out_dir: {SarifEnv().out_dir}")
        if self.out_dir is None:
            # sootup_out_dir = SarifEnv().out_dir / "SootUp"
            sootup_out_dir = SarifEnv().out_dir
        else:
            sootup_out_dir = self.out_dir

        if not sootup_out_dir.exists():
            sootup_out_dir.mkdir(parents=True, exist_ok=True)

        container_name = f"sootup_{self.cp.language}_{self.cp.name}_{int(time.time())}"
        logger.info(f"SootUp out dir: {sootup_out_dir}")
        self.container: Container = self.client.containers.run(
            image=self.image_name,
            command=["/bin/bash"],
            detach=True,
            tty=True,
            stdin_open=True,
            name=container_name,  # Set the container name
            volumes={sootup_out_dir.as_posix(): {"bind": "/out", "mode": "rw"}},
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
                f"sootup_{self.cp.language}_{self.cp.name}_"
            ):
                try:
                    container.stop()
                    container.remove()
                    logger.debug(
                        f"Cleaned up container {container.id} with name {container.name}"
                    )
                except Exception as e:
                    logger.warning(f"Failed to clean up container {container.id}: {e}")


    def create_callgraph(self):
        start_time = time.time()
        logger.debug(f"Creating call graph")

        cmd = "mkdir -p /out/SootUp"
        self._exec(cmd)

        if self.mode != "pta":
            cmd = " ".join(
                [
                    "bash -c",
                    f"'/usr/lib/jvm/java-17-openjdk-amd64/bin/java -jar /opt/sootup/target/sootup-reachability.jar get-all-reachable-methods --cg-method {self.mode} --output-dir /out/SootUp --dump-call-graph /out/jars'",
                ]
            )
        else:
            if self.pta_algorithm == "insens": abb_pta_algorithm = "insens"
            elif self.pta_algorithm == "callsite_sensitive_1": abb_pta_algorithm = "1c"
            elif self.pta_algorithm == "callsite_sensitive_2": abb_pta_algorithm = "2c"
            elif self.pta_algorithm == "object_sensitive_1": abb_pta_algorithm = "1o"
            elif self.pta_algorithm == "object_sensitive_2": abb_pta_algorithm = "2o"
            elif self.pta_algorithm == "type_sensitive_1": abb_pta_algorithm = "1t"
            elif self.pta_algorithm == "type_sensitive_2": abb_pta_algorithm = "2t"
            elif self.pta_algorithm == "hybrid_object_sensitive_1": abb_pta_algorithm = "1h"
            elif self.pta_algorithm == "hybrid_object_sensitive_2": abb_pta_algorithm = "2h"
            elif self.pta_algorithm == "hybrid_type_sensitive_1": abb_pta_algorithm = "1ht"
            elif self.pta_algorithm == "hybrid_type_sensitive_2": abb_pta_algorithm = "2ht"
            elif self.pta_algorithm == "eagle_object_sensitive_1": abb_pta_algorithm = "E-1o"
            elif self.pta_algorithm == "eagle_object_sensitive_2": abb_pta_algorithm = "E-2o"
            elif self.pta_algorithm == "zipper_object_sensitive_1": abb_pta_algorithm = "Z-1o"
            elif self.pta_algorithm == "zipper_object_sensitive_2": abb_pta_algorithm = "Z-2o"
            elif self.pta_algorithm == "zipper_callsite_sensitive_1": abb_pta_algorithm = "Z-1c"
            elif self.pta_algorithm == "zipper_callsite_sensitive_2": abb_pta_algorithm = "Z-2c"            

            cmd = " ".join(
                [
                    "bash -c",
                    f"'/usr/lib/jvm/java-17-openjdk-amd64/bin/java -jar /opt/sootup/target/sootup-reachability.jar get-all-reachable-methods --cg-method {self.mode} --pta-algorithm {abb_pta_algorithm} --output-dir /out/SootUp --dump-call-graph /out/jars'",
                ]
            )
        self._exec(cmd)

        elapsed_time = time.time() - start_time
        logger.debug(f"Call graph creation completed in {elapsed_time} seconds")

    def run(self):
        self.create_callgraph()

        logger.debug("SootUp call graph generation completed")

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
            sootup_containers = [
                c for c in containers if c.name and c.name.startswith("sootup_")
            ]

            if not sootup_containers:
                logger.info("No SootUp containers found.")
                return

            print("\nAvailable SootUp containers:")
            for i, container in enumerate(sootup_containers):
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
                if choice < 1 or choice > len(sootup_containers):
                    logger.error("Invalid choice.")
                    return

                container = sootup_containers[choice - 1]
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
