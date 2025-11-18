import subprocess
import sys
from abc import ABC
from typing import NamedTuple

import docker
from docker.models.containers import Container, ExecResult


class ProcessRunRet(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


from loguru import logger


class BaseCommander(ABC):
    def __init__(self, quiet=False):
        self.quiet = quiet

    def run(
        self,
        cmd: str | list[str],
        input: str | None = None,
        cwd: str | None = None,
        pipe: bool = False,
        quiet: bool = False,
        timeout: int | None = None,
        stdout_file: str | None = None,
        stderr_file: str | None = None,
    ) -> ProcessRunRet:
        if isinstance(cmd, list):
            cmd = " ".join(cmd)

        if not quiet:
            logger.debug(f"Running command: {cmd}")

        try:
            if quiet:
                result = subprocess.run(
                    cmd,
                    input=input,
                    shell=True,
                    cwd=cwd,
                    check=True,
                    text=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout,
                )
            elif not pipe:
                result = subprocess.run(
                    cmd,
                    input=input,
                    shell=True,
                    cwd=cwd,
                    check=True,
                    text=True,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                    timeout=timeout,
                )
            else:
                result = subprocess.run(
                    cmd,
                    input=input,
                    shell=True,
                    cwd=cwd,
                    check=True,
                    text=True,
                    capture_output=True,
                    timeout=timeout,
                )

            return ProcessRunRet(result.returncode, result.stdout, result.stderr)

        except subprocess.CalledProcessError as e:
            logger.error(
                f"Error occurred while running CMD: {cmd} at {cwd}. Error: {e}"
            )

            return ProcessRunRet(e.returncode, e.stdout, e.stderr)

        except subprocess.TimeoutExpired as e:
            logger.error(f"Timeout occurred while running CMD: {cmd} at {cwd}")
            logger.error(e)

            return ProcessRunRet(-1, e.stdout, e.stderr)

        finally:
            if stdout_file and result.stdout:
                with open(stdout_file, "a") as f:
                    f.write(result.stdout)
            if stderr_file and result.stderr:
                with open(stderr_file, "a") as f:
                    f.write(result.stderr)


class DockerCommander(BaseCommander):
    def __init__(
        self,
        container_id: str | None = None,
        image_name: str | None = None,
        quiet=False,
    ):
        super().__init__(quiet)

        self.client = docker.from_env()

        if image_name == None and container_id == None:
            raise ValueError("Either image_name or container_id must be provided")
        elif container_id != None:
            self.container_id = container_id
            self.container = self.client.containers.get(container_id)

            logger.info(f"Connected to container {self.container_id}")
        else:
            self.image_name = image_name
            self.container: Container = self.client.containers.run(
                image_name, detach=True
            )
            self.container_id = self.container.id

            logger.info(f"Created container {self.container_id} from {self.image_name}")

    def run(
        self,
        cmd: str | list[str],
        input: str | None = None,
        cwd: str = "./",
        pipe: bool = False,
        quiet: bool = False,
        timeout: int | None = None,
        stdout_file: str | None = None,
        stderr_file: str | None = None,
    ) -> ProcessRunRet:
        if isinstance(cmd, list):
            cmd = " ".join(cmd)

        if not quiet:
            logger.debug(f"Running command: {cmd} in container {self.container_id}")

        try:
            result: ExecResult = self.container.exec_run(
                cmd,
                workdir=cwd,
                stdout=True,
                stderr=True,
                demux=True,
                timeout=timeout,
            )

            # if quiet:
            #     ...
            # elif not pipe:
            #     ...
            # else:
            #     ...

            return ProcessRunRet(
                result.exit_code,
                result.output[0].decode("utf-8"),
                result.output[1].decode("utf-8"),
            )

        except Exception as e:
            logger.error(f"Error occurred while running CMD: {cmd} at {cwd}")
            logger.error(e)

            return ProcessRunRet(-1, "", "")
