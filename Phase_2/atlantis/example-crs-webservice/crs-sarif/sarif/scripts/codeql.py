import time
from pathlib import Path
from typing import Literal

import click
from dotenv import load_dotenv
from loguru import logger

from sarif.context import init_context
from sarif.models import CP
from sarif.tools.codeql.analyze import run_codeql_analysis
from sarif.tools.codeql.database import Database
from sarif.tools.codeql.docker import CodeQLDocker

pass_cp = click.make_pass_decorator(CP)


@click.group()
@click.argument("cp_name", type=str)
@click.argument("language", type=click.Choice(["c", "cpp", "java"]))
@click.argument("config_path", type=click.Path(path_type=Path))
@click.pass_context
def sarif_cli(
    ctx: click.Context,
    cp_name: str,
    language: Literal["c", "cpp", "java"],
    config_path: Path,
):
    logger.info(f"config_path: {config_path}")
    cp = CP(name=cp_name, language=language, config_path=config_path)

    init_context(cp=cp, env_mode="local", debug_mode="release")

    ctx.obj = cp


@sarif_cli.command()
@click.option("--build_dir", type=click.Path(path_type=Path), default=None)
@pass_cp
def build_codeql_database(
    cp: CP,
    build_dir: Path,
):
    logger.debug("Run in docker mode")
    logger.debug(f"Benchmark name: {cp.name}")

    docker_obj = CodeQLDocker(
        cp,
        build_dir=build_dir,
    )

    start_time = time.time()
    docker_obj.create_database()
    logger.debug(f"Total time taken: {time.time() - start_time} seconds")


@sarif_cli.command()
@click.option("--build_dir", type=click.Path(path_type=Path), default=None)
@click.option("--qlpack", type=str, default=None)
@pass_cp
def run_codeql_analysis_in_docker(
    cp: CP,
    build_dir: Path,
    qlpack: str | None,
):
    logger.debug("Run in docker mode")
    logger.debug(f"Benchmark name: {cp.name}")

    docker_obj = CodeQLDocker(
        cp,
        build_dir=build_dir,
    )

    start_time = time.time()
    docker_obj.create_database()
    docker_obj.analyze_database(qlpack)
    logger.debug(f"Total time taken: {time.time() - start_time} seconds")


if __name__ == "__main__":
    sarif_cli()
