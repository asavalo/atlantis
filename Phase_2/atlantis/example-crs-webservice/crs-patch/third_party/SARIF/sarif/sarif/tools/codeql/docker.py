import os
import time
from pathlib import Path

from docker.models.containers import Container
from loguru import logger

from sarif.models import CP
from sarif.utils.docker import OSSFuzzDocker


class CodeQLDocker(OSSFuzzDocker):
    tool_name: str = "codeql"
    build_name: str = "codeql-db"
    dockerfile = """
        FROM {}

        RUN cd /tmp
        RUN wget https://github.com/github/codeql-cli-binaries/releases/download/v2.20.4/codeql-linux64.zip --no-check-certificate
        RUN unzip codeql-linux64.zip
        RUN mv codeql /opt/codeql
        RUN rm codeql-linux64.zip
        RUN ln -s /opt/codeql/codeql /usr/local/bin/codeql

        # Clone CodeQL repository for standard libraries
        # RUN git clone --depth=1 https://github.com/github/codeql.git /opt/codeql-repo

        # Set up CodeQL configuration
        # RUN mkdir -p ~/.config/codeql
        # RUN echo "query-cache-size = 4" > ~/.config/codeql/config
        
        # Add CodeQL repository to search path
        # ENV CODEQL_SEARCH_PATH=/opt/codeql-repo

        # Install CodeQL query packs
        RUN codeql pack download codeql/java-queries:codeql-java
        RUN codeql pack download codeql/cpp-queries:codeql-cpp
        RUN codeql resolve qlpacks

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
                "PROJECT_NAME": f"aixcc/{self.cp.language}/{self.cp.name}",
                "HELPER": "True",
                "FUZZING_LANGUAGE": self.cp.language,
            }

        self.container: Container = self.client.containers.run(
            image=self.image_name,
            command=["/bin/bash"],
            detach=True,
            tty=True,
            stdin_open=True,
            volumes={
                str((self.build_dir / "codeql-db").resolve()): {
                    "bind": "/out/codeql-db",
                    "mode": "rw",
                }
            },
            environment=env,
        )

        logger.debug(f"Container {self.container.id} started")

        return self.container

    def create_database(self):
        db_path = f"/out/codeql-db/{self.cp.name}"

        # Check if codeql database already exists
        result = self.container.exec_run(f"test -d {db_path}/codeql-database.yml")
        if result.exit_code == 0:
            logger.debug(f"Database already exists at {db_path}, skipping creation")
            return

        # result = self.container.exec_run(f"test -d {db_path}")
        # if result.exit_code == 0:
        #     logger.debug(
        #         f"Directory {db_path} already exists, but it is not a codeql database. Removing dir."
        #     )
        #     self.container.exec_run(f"rm -rf {db_path}")

        logger.debug(f"Creating database for {self.cp.language}")
        # Check elapsed time
        start_time = time.time()

        # codeql database create --language=java --source-root=/src --command="/bin/bash /src/build.sh" /out/codeql-database
        if self.cp.language == "java":
            build_cmd = '"/bin/bash /src/build.sh"'
        else:
            build_cmd = '"compile"'

        cmd = " ".join(
            [
                "codeql",
                "database",
                "create",
                "--language=" + self.cp.language,
                "--source-root=.",
                "--threads=" + str(int(os.cpu_count() * 0.8)),
                "--command=" + build_cmd,
                db_path,
            ]
        )

        logger.debug(f"Command: {cmd}")
        result = self.container.exec_run(cmd, stdout=True, stderr=True)

        logger.debug(f"Command output: {result.output.decode()}")
        if result.exit_code != 0:
            logger.error(f"Command failed with exit code: {result.exit_code}")

        elapsed_time = time.time() - start_time
        logger.debug(
            f"Database created for {self.cp.language} in {elapsed_time} seconds"
        )

    def analyze_database(self, qlpack: str | None = None):
        logger.debug(f"Analyzing database for {self.cp.language}")
        # Check elapsed time
        start_time = time.time()

        if qlpack:
            qlpack_name = qlpack.split("/")[-1].split(".")[0]
            output_path = (
                f"/out/codeql-db/{self.cp.name}/codeql-analysis_{qlpack_name}.sarif"
            )
        else:
            output_path = f"/out/codeql-db/{self.cp.name}/codeql-analysis.sarif"

        result = self.container.exec_run(
            " ".join(
                [
                    "codeql",
                    "database",
                    "analyze",
                    f"/out/codeql-db/{self.cp.name}",
                    qlpack if qlpack else "",
                    "--threads=" + str(int(os.cpu_count() * 0.8)),
                    "--output=" + output_path,
                    "--format=sarif-latest",
                ]
            ),
            stdout=True,
            stderr=True,
        )

        logger.debug(f"Command output: {result.output.decode()}")
        if result.exit_code != 0:
            logger.error(f"Command failed with exit code: {result.exit_code}")

        elapsed_time = time.time() - start_time
        logger.debug(
            f"Database analyzed for {self.cp.language} in {elapsed_time} seconds"
        )
