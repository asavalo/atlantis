import json
import os
import shutil
from pathlib import Path
from typing import List

import click
from pygit2 import Repository

from scripts.benchmark.models import BenchmarkReport


@click.command()
@click.option(
    "--reports-directory",
    help="Reports directory",
    type=click.Path(exists=False, file_okay=False, dir_okay=True, path_type=Path),
    default=Path(__file__).parent.parent.parent / "reports",
)
def main(
    reports_directory: Path,
):
    runners: List[str] = json.loads(os.environ["BENCHMARK_NODES"])

    _assert_valid_reports_directory(reports_directory)

    for runner in runners:
        collect_dir = reports_directory / runner
        if collect_dir.exists():
            shutil.rmtree(collect_dir)
        collect_dir.mkdir(parents=True, exist_ok=True)
    return


def _assert_valid_reports_directory(reports_directory: Path):
    repository = Repository(".")  # FIXME: This is a hardcoded path
    head_commit = repository[repository.head.target].peel(1)
    commit_hash = str(head_commit.id)
    commit_timestamp = head_commit.commit_time

    for report_file in reports_directory.glob("*.json"):
        report = BenchmarkReport.load(report_file)
        assert (
            report.commit_hash == commit_hash
            and report.commit_timestamp == commit_timestamp
        ), (
            f'Report directory "{reports_directory}" is from a different commit. Please remove it.'
        )


if __name__ == "__main__":
    main()
