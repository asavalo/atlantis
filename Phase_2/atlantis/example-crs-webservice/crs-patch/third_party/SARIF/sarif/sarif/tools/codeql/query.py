import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Dict, Literal

from jinja2 import Template
from loguru import logger

from sarif.tools.codeql.bqrs import BQRS
from sarif.tools.codeql.common import run, temporary_file


def _check_codeql_db(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Database not found at {path}")

    if not path.is_dir():
        raise ValueError(f"Database is not a directory: {path}")

    if (
        not path.joinpath("db-java").exists()
        and not path.joinpath("db-cpp").exists()
        and not path.joinpath("db-c").exists()
    ):
        raise ValueError(f"Database is not a CodeQL database: {path}")

    return True


class Query:
    def __init__(
        self,
        path: Path,
        lang: Literal["c", "java"],
        require_format: bool = False,
        required_params: list[str] | None = None,
        required_external: list[str] | None = None,
    ):
        self.lang = lang
        self.path = path
        self.require_format = require_format
        self.required_params = required_params
        self.required_external = required_external
        self.is_jinja = self.path.suffix == ".jinja2"

    @staticmethod
    def from_source(code):
        path = temporary_file(suffix=".ql")

        with open(path, mode="w") as f:
            f.write(code)

        return Query(path)

    @staticmethod
    def from_file(path):
        return Query(path)

    def compile(self):
        self.run_command("compile")

    def run_command(self, command, options=[], post=[]):
        run(["query", command] + options + [self.path] + post)

    def run(
        self,
        database: str | Path,
        output: Path | None = None,
        external: dict = {},
        params: Dict | None = None,
    ) -> BQRS:
        database = Path(database)

        _check_codeql_db(database)

        if self.require_format and not params:
            raise ValueError("Query requires parameters")

        if self.required_params:
            for param in self.required_params:
                if param not in params:
                    raise ValueError(f"Query requires parameter {param}")

        if self.required_external:
            for external_name in self.required_external:
                if external_name not in external:
                    raise ValueError(f"Query requires external {external_name}")

        logger.debug(f"Running query {self.path} on database {database}")
        start_time = time.time()

        if output is None:
            output = temporary_file(suffix=".bqrs")

        options = [
            "-o",
            output.as_posix(),
            "-d",
            database.as_posix(),
            "-j",
            os.getenv("CODEQL_THREADS", 4),
            "-M",
            os.getenv("CODEQL_RAM", 4096),
        ]

        if external:
            for k, v in external.items():
                options += [f"--external={k}={v}"]

        if self.is_jinja:
            with open(self.path, "r") as template_f:
                template = Template(template_f.read())
            if params:
                f_query_content = template.render(**params)
            else:
                f_query_content = template.render()

            f_query_path = temporary_file(prefix=self.path.stem + "_", suffix=".ql")

            # cp qlpack.yml and codeql-pack.lock.yml to f_query_path directory
            shutil.copy(self.path.parent / "qlpack.yml", f_query_path.parent)
            shutil.copy(self.path.parent / "codeql-pack.lock.yml", f_query_path.parent)
            for qll_file in self.path.parent.glob("*.qll"):
                shutil.copy(qll_file, f_query_path.parent)

            with open(f_query_path, "w") as query_f:
                query_f.write(f_query_content)

            run(["query", "run"] + options + [f_query_path])

            os.remove(f_query_path)
        else:
            self.run_command("run", options)

        end_time = time.time()
        logger.debug(f"Query {self.path} completed in {end_time - start_time} seconds")

        return BQRS(output)
