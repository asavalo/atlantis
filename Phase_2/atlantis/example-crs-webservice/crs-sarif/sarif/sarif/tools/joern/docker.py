import time
from pathlib import Path

from docker.models.containers import Container
from loguru import logger

from sarif.models import CP
from sarif.utils.docker import OSSFuzzDocker


class JoernDocker(OSSFuzzDocker):
    tool_name: str = "joern"
    build_name: str = "joern-cpg"
    dockerfile = """
        FROM {}

        WORKDIR /tmp

        ENV JOERN_INSTALL_DIR=/joern
        ENV JOERN_VERSION=v4.0.258

        RUN apt-get update && \
            apt-get install -y openjdk-21-jdk libssl1.1 curl && \
            apt-get clean

        RUN apt-get install -y --reinstall libssl1.1 libcurl4 && \
            ln -sf /usr/lib/x86_64-linux-gnu/libssl.so.1.1 /usr/local/lib/libssl.so.1.1 && \
            ln -sf /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 /usr/local/lib/libcrypto.so.1.1 && \
            ldconfig

        RUN wget https://github.com/joernio/joern/releases/download/$JOERN_VERSION/joern-install.sh --no-check-certificate
        RUN chmod +x joern-install.sh
        RUN ./joern-install.sh --install-dir=$JOERN_INSTALL_DIR --version=$JOERN_VERSION --reinstall

        CMD ["/bin/bash"]
        """

    def __init__(
        self,
        cp: CP,
        *,
        build_dir: Path | None = None,
    ):
        super().__init__(cp)

        if build_dir is not None:
            self.build_dir = build_dir

    def _start_container(self):
        if self.cp.language == "java":
            env = {}
        else:
            env = {
                "FUZZING_ENGINE": "libfuzzer",
                "SANITIZER": "address",
                "ARCHITECTURE": "x86_64",
                "PROJECT_NAME": f"aixcc/c/{self.cp.name}",
                "HELPER": "True",
                "FUZZING_LANGUAGE": "c",
            }

        self.container: Container = self.client.containers.run(
            image=self.image_name,
            command=["/bin/bash"],
            detach=True,
            tty=True,
            stdin_open=True,
            volumes={
                str((self.build_dir).resolve()): {
                    "bind": "/out/joern-cpg",
                    "mode": "rw",
                }
            },
            environment=env,
        )

        logger.debug(f"Container {self.container.id} started")

        return self.container

    def create_cpg(self):
        cpg_path = f"/out/joern-cpg/{self.cp.name}.cpg.bin"

        # Check if joern cpg already exists

        result = self.container.exec_run(f"test -f {cpg_path}")
        if result.exit_code == 0:
            logger.debug(f"Database already exists at {cpg_path}, skipping creation")
            return

        logger.debug(f"Creating CPG for {self.cp.name}")

        # Check elapsed time
        start_time = time.time()

        match self.cp.language:
            case "c":
                cmd = " ".join(
                    [
                        f"/joern/joern-cli/c2cpg.sh",
                        "/src",
                        "--exclude=/src/aflplusplus",
                        "--exclude=/src/fuzztest",
                        "--exclude=/src/honggfuzz",
                        "--exclude=/src/libfuzzer",
                        "-J-Xmx12g",
                        "--output=" + cpg_path,
                    ]
                )
            case "cpp":
                cmd = " ".join(
                    [
                        f"/joern/joern-cli/c2cpg.sh",
                        "/src",
                        "--exclude=/src/aflplusplus",
                        "--exclude=/src/fuzztest",
                        "--exclude=/src/honggfuzz",
                        "--exclude=/src/libfuzzer",
                        "-J-Xmx12g",
                        "--output=" + cpg_path,
                    ]
                )
            case "java":
                cmd = " ".join(
                    [
                        f"/joern/joern-cli/javasrc2cpg",
                        "/src",
                        "--exclude=/src/aflplusplus",
                        "--exclude=/src/fuzztest",
                        "--exclude=/src/honggfuzz",
                        "--exclude=/src/libfuzzer",
                        "-J-Xmx12g",
                        "--output=" + cpg_path,
                    ]
                )

        logger.debug(f"Command: {cmd}")
        result = self.container.exec_run(cmd, stdout=True, stderr=True)

        if result.exit_code != 0:
            logger.error(f"Command failed with exit code: {result.exit_code}")

        elapsed_time = time.time() - start_time
        logger.debug(f"CPG created for {self.cp.language} in {elapsed_time} seconds")
