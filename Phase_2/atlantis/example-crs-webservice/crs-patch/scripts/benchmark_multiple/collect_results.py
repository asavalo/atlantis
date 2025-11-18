import importlib
import json
import os
import shutil
from glob import glob
from pathlib import Path
from typing import Iterator, List

import click

from scripts.benchmark.models import BenchmarkReport


@click.command()
@click.option(
    "--module",
    "-m",
    help="""App to run ([module]:[object])""",
    required=False,
    default=None,
    multiple=True,
    type=str,
)
@click.option(
    "--reports-directory",
    help="Reports directory",
    type=click.Path(exists=False, file_okay=False, dir_okay=True, path_type=Path),
    default=Path(__file__).parent.parent.parent / "reports",
)
def main(
    module: list[str],
    reports_directory: Path,
):
    runners: List[str] = json.loads(os.environ["BENCHMARK_NODES"])

    modules = (
        list(_all_modules())
        if len(module) == 0
        else [_verified_module(m) for m in module]
    )

    for app in modules:
        app_name = app.removeprefix("apps.")
        report_path = reports_directory / f"{app_name}.json"
        for result_path in reports_directory.glob(f"*/{app_name}.json"):
            if report_path.exists():
                BenchmarkReport.load(result_path).append(report_path)
            else:
                BenchmarkReport.load(result_path).save(report_path)
            os.remove(result_path)

    for runner in runners:
        output_directory = reports_directory / runner
        for app_path in output_directory.glob("*"):
            for detection_path in app_path.glob("*"):
                app = app_path.name
                detection = detection_path.name
                if (reports_directory / app / detection).exists():
                    shutil.rmtree(reports_directory / app / detection)
                shutil.copytree(
                    output_directory / app / detection,
                    reports_directory / app / detection,
                )

        if output_directory.exists():
            shutil.rmtree(output_directory)


def _all_modules() -> Iterator[str]:
    for path in glob("apps/**/*.py", recursive=True):
        module_name = Path(path).stem
        if module_name.startswith("_") or module_name.startswith("."):
            continue
        module = path.removesuffix(".py").replace("/", ".")
        assert module.startswith("apps.")
        yield _verified_module(module)


def _verified_module(module: str) -> str:
    try:
        importlib.import_module(module)
    except ImportError:
        raise ValueError(f"Could not import module {module}")

    return module


if __name__ == "__main__":
    main()
