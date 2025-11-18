import json
import os
from pathlib import Path
from typing import Literal

from loguru import logger

from sarif.tools.codeql.common import run, temporary_dir
from sarif.tools.codeql.database import Database


def run_codeql_analysis(
    db: Database,
    run_name: str,
    language: Literal["c", "java"],
    output: Path | None = None,
    split_results: bool = False,
    extended: bool = False,
) -> None:
    # Create temporary directory for analysis results
    if output is None:
        output = temporary_dir() / f"{run_name}.sarif"

    nproc = os.cpu_count()

    # Run CodeQL analysis based on language
    if language == "c":
        run(
            [
                "database",
                "analyze",
                str(db.path),
                "--format=sarif-latest",
                "--threads=" + str(int(nproc / 2)),
                "--verbose",
                "--output",
                output,
                "cpp-security-extended.qls" if extended else "",
            ],
        )
    elif language == "java":
        run(
            [
                "database",
                "analyze",
                str(db.path),
                "--format=sarif-latest",
                "--threads=" + str(int(nproc / 2)),
                "--verbose",
                "--output",
                output,
                "java-security-extended.qls" if extended else "",
            ],
        )
