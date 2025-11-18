import datetime
import importlib
import logging
import shutil
import time
import traceback
from dataclasses import dataclass
from glob import glob
from pathlib import Path
from typing import Iterator, List, Optional

import click
import litellm
from crete.atoms.report import CreteResult, DiffResult, ErrorResult, NoPatchResult
from crete.commons.logging.hooks import use_logger
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.crete.models import Crete
from openinference.instrumentation import using_session
from pygit2 import Repository
from python_aixcc_challenge.project.functions import (
    prepare_aixcc_challenge_projects_from_detection_files,
)
from tqdm import tqdm

from scripts.benchmark.functions import (
    execute_in_process,
    logging_standard_output,
    tracking_llm_cost,
)
from scripts.benchmark.models import BenchmarkReport, BenchmarkResult
from scripts.benchmark.verifiers import (
    verify_patch_with_crete,
    verify_patch_with_patch_checker,
)

litellm.suppress_debug_info = True

_logger = use_logger()


@dataclass(frozen=True)
class BenchmarkArguments:
    timeout: int
    llm_cost_limit: float


@click.command()
@click.argument(
    "detection-files",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    nargs=-1,
)
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
    "--cache-directory",
    help="Cache directory",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=Path(__file__).parent.parent.parent / ".cache",
    required=False,
)
@click.option(
    "--reports-directory",
    help="Reports directory",
    type=click.Path(exists=False, file_okay=False, dir_okay=True, path_type=Path),
    default=Path(__file__).parent.parent.parent / "reports",
)
@click.option(
    "--timeout-for-app",
    help="Timeout for each app in seconds (default: None)",
    type=Optional[int],
    default=None,
)
@click.option(
    "--timeout",
    help="Timeout for each app and detection in seconds (default: 5 minutes)",
    type=int,
    default=5 * 60,  # 5 minutes
)
@click.option(
    "--llm-cost-limit",
    help="LLM cost limit for each app and detection in dollars (default: 3.0)",
    type=float,
    default=3.0,  # 3 dollars
)
@click.option(
    "--keep-best-result",
    help="Instead of deleting the contents of the report directory, replace the existing contents only if the execution results are better than or equal to the previous execution; otherwise, retain the existing contents (default: False)",
    is_flag=True,
    default=False,
)
@click.option(
    "--early-exit-on-sound",
    help="Execution will not be performed if the existing patch is sound (valid only when the --keep-best-result option is enabled, default: False)",
    is_flag=True,
    default=False,
)
def run(
    detection_files: tuple[Path],
    module: list[str],
    cache_directory: Path,
    reports_directory: Path,
    timeout_for_app: Optional[int],
    timeout: int,
    llm_cost_limit: float,
    keep_best_result: bool,
    early_exit_on_sound: bool,
):
    """\b
    Run benchmarks for Crete, targeting apps/*.py directory. 
    If --module is not provided, all apps/*.py will be run.


    \b
    Example:
    $ uv run benchmark \\
            --module apps.aider_only \\
            --cache-directory /tmp/.cache \\
            --reports-directory reports \\
            detection-files/*.toml
    """

    _assert_valid_reports_directory(reports_directory)

    assert timeout_for_app is None or timeout_for_app > timeout, (
        "Timeout for each application should be greater than the timeout for each instance"
    )

    modules = (
        list(_all_modules())
        if len(module) == 0
        else [_verified_module(m) for m in module]
    )

    active_detection_files = list(
        filter(lambda x: not x.stem.startswith("_"), detection_files)
    )

    challenge_project_directories = (
        prepare_aixcc_challenge_projects_from_detection_files(
            list(active_detection_files), cache_directory
        )
    )

    benchmark_arguments = BenchmarkArguments(
        timeout=timeout,
        llm_cost_limit=llm_cost_limit,
    )

    for app_module in tqdm(modules, desc="Apps", dynamic_ncols=True, colour="blue"):
        app_name = app_module.removeprefix("apps.")
        benchmark_results: List[BenchmarkResult] = []
        for challenge_project_directory, detection_file in tqdm(
            zip(challenge_project_directories, active_detection_files),
            desc="Running",
            unit="detection",
            dynamic_ncols=True,
            leave=False,
            colour="green",
        ):
            output_directory = reports_directory / app_name / detection_file.stem
            prev_result = None

            if keep_best_result:
                try:
                    prev_result = BenchmarkResult.load(output_directory / "result.json")
                except Exception:
                    pass

                if prev_result is not None:
                    if early_exit_on_sound and prev_result.variant == "sound":
                        continue
                    output_directory = (
                        reports_directory / app_name / (detection_file.stem + "_tmp")
                    )

            if output_directory.exists():
                shutil.rmtree(output_directory)
            output_directory.mkdir(parents=True, exist_ok=True)

            result = execute_in_process(
                _run_single_benchmark,
                (
                    app_module,
                    challenge_project_directory,
                    output_directory,
                    detection_file,
                    benchmark_arguments,
                ),
                timeout_for_app,
            )
            (output_directory / "result.json").write_text(result.model_dump_json())

            if keep_best_result and prev_result is not None:
                if not result.is_worse_than(prev_result):
                    shutil.rmtree(reports_directory / app_name / detection_file.stem)
                    shutil.copytree(
                        output_directory,
                        reports_directory / app_name / detection_file.stem,
                    )
                else:
                    result = prev_result
                shutil.rmtree(output_directory)

            benchmark_results.append(result)

        report_path = reports_directory / f"{app_name}.json"
        if report_path.exists():
            BenchmarkReport.from_benchmark_results(app_name, benchmark_results).append(
                report_path
            )
        else:
            BenchmarkReport.from_benchmark_results(app_name, benchmark_results).save(
                report_path
            )


def _run_crete_app(
    app_module: str,
    challenge_project_directory: Path,
    output_directory: Path,
    detection_file: Path,
    benchmark_arguments: BenchmarkArguments,
) -> CreteResult:
    with logging_standard_output(
        output_directory / "stdout.txt",
        output_directory / "stderr.txt",
    ):
        try:
            context_builder = AIxCCContextBuilder(
                challenge_project_directory,
                detection_file,
                logging_level=logging.INFO,
                output_directory=output_directory,
            )
            return _import_app(app_module).run(
                context_builder=context_builder,
                timeout=benchmark_arguments.timeout,
                llm_cost_limit=benchmark_arguments.llm_cost_limit,
                output_directory=output_directory,
            )
        except Exception:
            traceback.print_exc()
            raise


def _get_patch_result_from_crete_result(crete_result: CreteResult) -> str:
    match crete_result:
        case NoPatchResult(variant=variant):
            return f"No patch found ({variant})"
        case DiffResult(variant=variant, diff=_):
            return f"Patch found ({variant})"
        case ErrorResult(variant=variant, error=_):
            return f"Error ({variant})"


def _run_single_benchmark(
    app_module: str,
    challenge_project_directory: Path,
    output_directory: Path,
    detection_file: Path,
    benchmark_arguments: BenchmarkArguments,
) -> BenchmarkResult:
    start_time = time.time()
    llm_cost = 0

    def _update_llm_cost(cost: float):
        nonlocal llm_cost
        llm_cost += cost

    try:
        with tracking_llm_cost(_update_llm_cost):
            current_time = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
            session_id = f"{app_module}-{detection_file.stem}-{current_time}"
            with using_session(session_id=session_id):
                crete_result = _run_crete_app(
                    app_module,
                    challenge_project_directory,
                    output_directory,
                    detection_file,
                    benchmark_arguments,
                )

        elapsed_time = int(time.time() - start_time)

        # Sarif detection does not contain the blob file. Instead, we use full-mode detection file to verify the patch.
        if detection_file.stem.endswith("-sarif") and crete_result.variant == "sound":
            if validation_detection_file := _detection_from_sarif_detection_file(
                detection_file
            ):
                crete_result = verify_patch_with_crete(
                    validation_detection_file,
                    challenge_project_directory,
                    output_directory / f"final-{crete_result.variant}.diff",
                )

        # Verify with PatchChecker, which is used by CRS-Patch.
        if crete_result.variant == "sound":
            old_crete_result = crete_result
            crete_result = verify_patch_with_patch_checker(
                detection_file,
                challenge_project_directory,
                output_directory / f"final-{crete_result.variant}.diff",
            )
            if crete_result.variant != old_crete_result.variant:
                _logger.warning(
                    f"PatchChecker result ({crete_result.variant}) is different from Crete result ({old_crete_result.variant})"
                )
            else:
                _logger.info("PatchChecker result: SOUND")

        _logger.info(
            f"{detection_file.stem} result:\n"
            f"  Patch: {_get_patch_result_from_crete_result(crete_result)}\n"
            f"  Elapsed time: {elapsed_time} seconds\n"
            f"  LLM cost: {llm_cost} dollars\n",
            extra={
                "elapsed_time": elapsed_time,
                "llm_cost": llm_cost,
            },
        )

        return BenchmarkResult.from_crete_result(
            crete_result,
            detection_file.stem,
            elapsed_time,
            llm_cost,
        )
    except Exception as e:
        return BenchmarkResult.model_validate(
            {
                "cpv_name": detection_file.stem,
                "variant": "unknown_error",
                "message": str(e),
                "elapsed_time": int(time.time() - start_time),
                "llm_cost": llm_cost,
            }
        )


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


def _import_app(module: str) -> Crete:
    parts = module.split(":", 1)
    if len(parts) == 1:
        obj = "app"
    else:
        module, obj = parts[0], parts[1]

    try:
        mod = importlib.import_module(module)
    except ImportError:
        raise ValueError(f"Could not import module {module}")

    try:
        app = getattr(mod, obj)
    except AttributeError:
        raise ValueError(f"Module {module} has no attribute {obj}")

    if not isinstance(app, Crete):
        raise ValueError(f"Object {obj} in module {module} is not a Crete app")

    return app


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


def _detection_from_sarif_detection_file(detection_file: Path) -> Path | None:
    parent_dir = detection_file.parent.parent
    file_stem = detection_file.stem.replace("-sarif", "")
    detection_file = parent_dir / "full" / f"{file_stem}-full.toml"
    _logger.info(f"Sarif file detected. Using full detection file: {detection_file}")
    if not detection_file.exists():
        _logger.warning(f"Full detection file not found: {detection_file}")
        return None
    return detection_file


@click.command()
@click.argument(
    "source-directory",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    required=True,
)
@click.argument(
    "destination-directory",
    type=click.Path(exists=False, file_okay=False, dir_okay=True, path_type=Path),
    required=True,
)
def merge(
    source_directory: Path,
    destination_directory: Path,
):
    """Merge benchmark reports from one directory to another.

    \b
    source-directory: Reports directory to be merged
    destination-directory: Output directory to merge reports into
    """
    assert source_directory.exists()
    assert destination_directory.exists()

    source_reports_jsons = source_directory.glob("*.json")
    for source_report_path in source_reports_jsons:
        application_name = source_report_path.stem
        output_report_path = destination_directory / source_report_path.name
        if output_report_path.exists():
            BenchmarkReport.load(source_report_path).append(output_report_path)
        else:
            output_report_path.write_text(source_report_path.read_text())

        for detection_path in (source_directory / application_name).glob("*"):
            detection_name = detection_path.name
            if (destination_directory / application_name / detection_name).exists():
                shutil.rmtree(destination_directory / application_name / detection_name)
            shutil.copytree(
                source_directory / application_name / detection_name,
                destination_directory / application_name / detection_name,
            )


if __name__ == "__main__":
    run()
