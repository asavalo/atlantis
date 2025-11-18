import time
from pathlib import Path
from typing import Literal

import click
from dotenv import load_dotenv

from sarif.context import init_context
from sarif.models import CP
from sarif.tools.codeql.analyze import run_codeql_analysis
from sarif.tools.codeql.database import Database
from sarif.tools.codeql.docker import CodeQLDocker
from sarif.tools.SootUp.docker import SootupDocker
from loguru import logger

pass_cp = click.make_pass_decorator(CP)


@click.group()
@click.argument("cp_name", type=str)
@click.argument("language", type=click.Choice(["java", "jvm"]))
@click.argument("config_path", type=click.Path(path_type=Path))
@click.pass_context
def sarif_cli(
    ctx: click.Context,
    cp_name: str,
    language: Literal["java", "jvm"],
    config_path: Path,
):
    cp = CP(name=cp_name, language=language, config_path=config_path)

    init_context(cp=cp, env_mode="local", debug_mode="release")

    ctx.obj = cp


@sarif_cli.command()
@click.option("--out-dir", type=click.Path(path_type=Path))
@click.option(
    "--mode",
    type=click.Choice(
        ["cha", "rta", "pta"]
    ),
)
@pass_cp
def run_sootup_in_docker(
    cp: CP,
    out_dir: Path | None = None,
    mode: Literal["cha", "rta", "pta"] = "cha",
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
):
    if cp.language == "c" or cp.language == "cpp":
        raise ValueError("Sootup does not support C/C++")

    logger.debug("Run in docker mode")
    logger.debug(f"Benchmark name: {cp.name}")

    docker_obj = SootupDocker(
        cp,
        out_dir=out_dir,
        mode=mode,
        pta_algorithm=pta_algorithm,
    )

    start_time = time.time()
    docker_obj.run()
    logger.debug(f"Total time taken: {time.time() - start_time} seconds")
    docker_obj.attach_to_container()


if __name__ == "__main__":
    sarif_cli()
