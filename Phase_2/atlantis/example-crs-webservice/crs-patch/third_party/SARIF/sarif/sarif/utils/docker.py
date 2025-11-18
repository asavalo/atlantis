from abc import ABC
from pathlib import Path

from docker import from_env
from docker.errors import ImageNotFound
from docker.models.containers import Container
from docker.models.images import Image
from loguru import logger

from sarif.context import SarifEnv, init_context
from sarif.models import CP


class OSSFuzzDocker(ABC):
    tool_name: str = "base"
    build_name: str = "base-db"
    dockerfile = """
        FROM {}

        CMD ["/bin/bash"]
    """

    def __init__(self, cp: CP, *, docker_file_path: Path | None = None):
        self.cp = cp
        self.docker_file_path = docker_file_path

        self.project_full_name = f"aixcc/{cp.oss_fuzz_lang}/{cp.name}"
        # self.ossfuzz_image_name = f"gcr.io/oss-fuzz/{self.project_full_name}"
        self.ossfuzz_image_name = f"aixcc-afc/{self.project_full_name}"
        self.image_name = f"{self.ossfuzz_image_name}-{self.tool_name}"

        self.build_dir = SarifEnv().build_dir / self.build_name

        self.client = from_env()

        try:
            self.client.images.get(self.image_name)
        except ImageNotFound:
            logger.debug(f"Image {self.image_name} not found")
            self.image_name = self._build_image()
        else:
            logger.debug(f"Image {self.image_name} already exists")

        self.container = self._start_container()

    def _exec(self, cmd: str, env: dict | None = None) -> bool:
        logger.debug(f"Command: {cmd}")
        result = self.container.exec_run(cmd, stdout=True, stderr=True, environment=env)

        logger.debug(f"Command output: {result.output.decode()}")
        if result.exit_code != 0:
            logger.error(f"Command failed with exit code: {result.exit_code}")
            return False
        else:
            return True

    def __del__(self):
        self._stop_container()

    def _build_image(self) -> Image:
        if self.dockerfile == "":
            logger.debug(
                f"Dockerfile is not set for {self.tool_name}. Use oss-fuzz docker image."
            )
            return self.client.images.get(self.ossfuzz_image_name)

        if self.docker_file_path is None:
            docker_path = Path(f"{self.build_dir}/dockerfiles")

            if not docker_path.exists():
                docker_path.mkdir(parents=True, exist_ok=True)

            self.docker_file_path = docker_path / self.cp.name / "Dockerfile"

        if not self.docker_file_path.parent.exists():
            self.docker_file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.docker_file_path, "w") as f:
            f.write(self.dockerfile.format(self.ossfuzz_image_name))

        logger.debug(f"Building image {self.image_name}")

        image, _ = self.client.images.build(
            path=self.docker_file_path.parent.as_posix(),
            dockerfile=self.docker_file_path.name,
            tag=self.image_name,
            quiet=True,
        )

        logger.debug(f"Image {self.image_name} built")

        return image

    def _start_container(self) -> Container:
        self.container = self.client.containers.run(
            image=self.image_name,
            command=["/bin/bash"],
            detach=True,
            tty=True,
            stdin_open=True,
        )

        logger.debug(f"Container {self.container.id} started")

        return self.container

    def _stop_container(self):
        if hasattr(self, "container") and self.container:
            try:
                self.container.stop()
                self.container.remove()
                logger.debug(f"Container {self.container.id} stopped and removed")
            except Exception as e:
                logger.warning(
                    f"Failed to stop/remove container {self.container.id}: {e}"
                )
            finally:
                self.container = None
