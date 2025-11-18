import os
import shutil
from pathlib import Path

from docker.models.images import Image
from loguru import logger

from sarif.context import SarifEnv
from sarif.models import CP
from sarif.utils.docker import OSSFuzzDocker


class IntrospectorDocker(OSSFuzzDocker):
    tool_name: str = "introspector"
    build_name: str = "introspector-db"
    dockerfile = """
        FROM {}
        COPY sarif /tmp/sarif

        # Download and save poetry install script with error handling
        RUN curl -sSL https://install.python-poetry.org -o /tmp/install-poetry.py || \
            rm -rf /usr/local/lib/libcrypto.so.1.1 /usr/local/lib/libssl.so.1.1 && \
            curl -sSL https://install.python-poetry.org -o /tmp/install-poetry.py

        # Install poetry
        RUN python3 /tmp/install-poetry.py

        # Install dependencies
        RUN cd /tmp/sarif && /root/.local/bin/poetry install

        CMD ["/bin/bash"]
        """

    def __init__(
        self,
        cp: CP,
        *,
        sarif_package_dir: Path | None = None,
        oss_fuzz_dir: Path | None = None,
    ):
        docker_file_path = (
            Path(self.sarif_package_dir).parent / "Dockerfile_introspector"
        )
        super().__init__(cp, docker_file_path=docker_file_path)

        self.sarif_package_dir = sarif_package_dir
        if self.sarif_package_dir is None:
            self.sarif_package_dir = os.path.join(os.getcwd(), "sarif")

        self.oss_fuzz_dir = oss_fuzz_dir

        if self.oss_fuzz_dir is None:
            self.oss_fuzz_dir = os.getenv("OSS_FUZZ_DIR")
            if self.oss_fuzz_dir is None:
                raise ValueError("OSS_FUZZ_DIR is not set")

        if self.cp.language == "c" or self.cp.language == "cpp":
            self.target_dir = "/src"
        else:
            self.target_dir = "/src/src"

    def update_sarif_package(self):
        # If image does not exist, build it
        if not self.client.images.list(self.image_name):
            self._build_image()
            return

        # Update the sarif package
        dockerfile = f"""
        FROM {self.image_name}
        
        # Backup the virtualenv
        RUN if [ -d "/tmp/sarif/.venv" ]; then \
            cp -r /tmp/sarif/.venv /tmp/.venv_backup; \
        fi
        
        # Copy new sarif code
        COPY sarif /tmp/sarif
        
        # Restore the virtualenv if backup exists
        RUN if [ -d "/tmp/.venv_backup" ]; then \
            rm -rf /tmp/sarif/.venv; \
            mv /tmp/.venv_backup /tmp/sarif/.venv; \
        fi

        CMD ["/bin/bash"]
        """

        docker_file_path = (
            Path(self.sarif_package_dir).parent / "Dockerfile_introspector"
        )

        with open(docker_file_path, "w") as f:
            f.write(dockerfile)

        self.client.images.build(
            path=docker_file_path.parent.as_posix(),
            dockerfile=docker_file_path.as_posix(),
            tag=self.image_name,
            quiet=False,
        )

        # Remove the dockerfile
        os.remove(docker_file_path)

        logger.debug(f"Image {self.image_name} updated")

    def run_sink_analysis(self):
        if self.output is None:
            self.output = (
                Path(os.getenv("DATA_DIR"))
                / self.cp.language
                / "out"
                / "introspector"
                / f"{self.cp.name}-sink_analysis.json"
            )

        if self.output.exists():
            logger.info(
                f"Sink analysis result already exists in {self.output}. Skipping..."
            )
            return

        logger.debug(f"Running sink analysis for {self.cp.name}...")

        # Check if the image exists. If not, build image using oss-fuzz scripts
        if not self.client.images.list(self.image_name):
            logger.debug(f"Image {self.image_name} not found, building it...")
            self._build_image()

        command = [
            "/bin/bash",
            "-c",
            f"cd /tmp/sarif && "
            f"/root/.local/bin/poetry run python -m sarif.dataset.sink_analysis "
            f"--language {self.cp.language} "
            f"--target-dir {self.target_dir} "
            # f"--harness-paths {' '.join(self.harness_file_paths)} "
            f"--out-dir /out/ ",
            # f"--output {self.output.as_posix()}",
        ]

        # Run the container
        self.client.containers.run(
            image=self.image_name,
            command=command,
            volumes={SarifEnv().out_dir.as_posix(): {"bind": "/out", "mode": "rw"}},
        )

        shutil.copy(SarifEnv().out_dir / "sink_analysis.json", self.output)

        logger.debug(f"Sink analysis for {self.cp.name} finished")

    def run_reachability(self):
        # Check whether the result already exists

        if self.output is None:
            self.output = (
                Path(os.getenv("DATA_DIR"))
                / self.cp.language
                / "out"
                / "introspector"
                / f"{self.cp.name}-reachability.json"
            )

        if self.output.exists():
            logger.info(
                f"Reachability result already exists in {self.output}. Skipping..."
            )
            return

        logger.debug(f"Running fuzz introspector for {self.cp.name}...")

        # Check if the image exists. If not, build image using oss-fuzz scripts
        if not self.client.images.list(self.image_name):
            logger.debug(f"Image {self.image_name} not found, building it...")
            self._build_image()

        command = [
            "/bin/bash",
            "-c",
            f"cd /tmp/sarif && "
            f"/root/.local/bin/poetry run python -m sarif.validator.reachability.introspector "
            f"--language {self.cp.language} "
            f"--target-dir /src "
            # f"--harness-paths {' '.join(self.harness_file_paths)} "
            f"--out-dir /out/ " f"--dump-functions True ",
            # f"--output {self.output.as_posix()}",
        ]

        self.client.containers.run(
            image=self.image_name,
            command=command,
            volumes={SarifEnv().out_dir.as_posix(): {"bind": "/out", "mode": "rw"}},
        )

        shutil.copy(
            SarifEnv().out_dir / "reachable_functions_introspector.json", self.output
        )

        logger.debug(f"Fuzz introspector for {self.cp.name} finished")
