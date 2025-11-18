import importlib
import itertools
import logging
import shutil
import sys
import time
import traceback
from dataclasses import dataclass
from glob import glob
from pathlib import Path
from typing import Iterator, List

import litellm
import pytest
from crete.atoms.report import CreteResult, DiffResult, ErrorResult, NoPatchResult
from crete.commons.logging.hooks import use_logger
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.crete.models import Crete
from pygit2 import Repository
from python_llm.api.actors import LlmApiManager

from scripts.benchmark.functions import (
    execute_in_process,
    logging_standard_output,
    tracking_llm_cost,
)
from scripts.benchmark.models import BenchmarkReport, BenchmarkResult

litellm.suppress_debug_info = True

_logger = use_logger()


@dataclass(frozen=True)
class BenchmarkArguments:
    timeout: int
    llm_cost_limit: float


models_to_try = [
    "openai/o3-mini",
    "openai/o1",
    "openai/o1-preview",
    "openai/o1-mini",
    "openai/gpt-4o-mini",
    "openai/gpt-4o",
    "openai/gpt-4-turbo",
    "openai/gpt-3.5-turbo",
    "openai/gpt-4",
    "claude-3-7-sonnet-20250219",
    "claude-3-opus-20240229",
    "claude-3-5-sonnet-20241022",
    "claude-3-5-haiku-20241022",
    "claude-3-sonnet-20240229",
    "claude-3-haiku-20240307",
]

# Same agents with different models
agent_groups = [
    {
        "aider_o1_mini",
        "aider_o1_preview",
        "aider_default",
        "aider_claude_3_5_sonnet",
    },
    {
        "line_range_patch_4o",
        "line_range_patch_o1",
        "line_range_patch_o3_mini",
    },
    {
        "search_replace_patch_4o",
        "search_replace_patch_o1",
        "search_replace_patch_o3_mini",
    },
    {"swe_o3_mini", "swe"},
]


def pytest_generate_tests(metafunc: pytest.Metafunc):
    """\b
    Run benchmarks for Crete, targeting apps/*.py directory, for all apps/*.py, with all models.

    \b
    Example:
    $ TEST_ALL_MODELS=1 uv run pytest \\
        "--self-contained-html" --html=pytest_report.html \\
        --record-mode=once --durations=0 --junitxml=pytest.xml \\
        --override-ini="log_cli=true" -vv \\
        tests/test_all_models.py
    """

    _assert_valid_reports_directory(reports_directory)

    assert timeout_for_app is None or timeout_for_app > timeout, (
        "Timeout for each application should be greater than the timeout for each instance"
    )

    modules = list({dedup_key(module): module for module in _all_modules()}.values())

    print("Agents:", modules)
    print("Models:", models_to_try)
    pairs = itertools.product(modules, models_to_try)
    metafunc.parametrize("agent, model_override", pairs)


def dedup_key(key: str) -> str:
    key = key.split(".")[-1]
    for x in agent_groups:
        if key in x:
            return sorted(x)[0]
    return key


keep_best_result = False
early_exit_on_sound = False
timeout_for_app = None
timeout = 5 * 60  # 5 minutes
llm_cost_limit = 3.0
reports_directory = Path(__file__).parent.parent.parent / "reports"


@pytest.mark.vcr()
def test_model_agent_c(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
    agent: str,
    model_override: str,
):
    _test_model_agent(detection_c_asc_nginx_cpv_1, agent, model_override)


@pytest.mark.vcr()
def test_model_agent_jvm(
    detection_jvm_mock_java_cpv_0: tuple[Path, Path],
    agent: str,
    model_override: str,
):
    _test_model_agent(detection_jvm_mock_java_cpv_0, agent, model_override)


def _test_model_agent(
    cpv: tuple[Path, Path],
    app_module: str,
    model_override: str,
):
    app_name = app_module.removeprefix("apps.")
    challenge_project_directory, detection_file = cpv
    base = reports_directory / "overrides" / model_override
    output_directory = base / app_name / detection_file.stem
    report_path = base / f"{app_name}.json"
    result_path = output_directory / "result.json"

    if result_path.exists() and report_path.exists():
        return

    benchmark_arguments = BenchmarkArguments(
        timeout=timeout,
        llm_cost_limit=llm_cost_limit,
    )

    if output_directory.exists():
        shutil.rmtree(output_directory)
    output_directory.mkdir(parents=True, exist_ok=True)

    result = execute_in_process(
        _run_single_benchmark_with_model_override,
        (
            app_module,
            challenge_project_directory,
            output_directory,
            detection_file,
            benchmark_arguments,
            model_override,
        ),
        timeout_for_app,
    )
    if result is None:
        pytest.skip(
            "The agent {} with model {} is skipped since it does not use LlmApiManager".format(
                app_module, model_override
            )
        )

    result_path.write_text(result.model_dump_json())

    benchmark_results: List[BenchmarkResult] = [result]
    app_name += "#" + model_override
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
    model_override: str,
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
            return _import_app_with_model_override(app_module, model_override).run(
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


def _run_single_benchmark_with_model_override(
    app_module: str,
    challenge_project_directory: Path,
    output_directory: Path,
    detection_file: Path,
    benchmark_arguments: BenchmarkArguments,
    model_override: str,
) -> BenchmarkResult | None:
    start_time = time.time()
    llm_cost = 0

    def _update_llm_cost(cost: float):
        nonlocal llm_cost
        llm_cost += cost

    try:
        with tracking_llm_cost(_update_llm_cost):
            crete_result = _run_crete_app(
                app_module,
                challenge_project_directory,
                output_directory,
                detection_file,
                benchmark_arguments,
                model_override,
            )

        elapsed_time = int(time.time() - start_time)

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
    except ShouldSkipError:
        return None
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


class ShouldSkipError(Exception):
    pass


def _import_app_with_model_override(module: str, model_override: str) -> Crete:
    parts = module.split(":", 1)
    if len(parts) == 1:
        obj = "app"
    else:
        module, obj = parts[0], parts[1]

    hook_called = False

    def hook(
        self: LlmApiManager,
        model: str,
        api_key: str,
        base_url: str,
        max_tokens: int | None = None,
        temperature: float = 1.0,
        custom_llm_provider: str | None = None,
    ):
        nonlocal hook_called
        _logger.info(f"Model override: {model_override}")
        model = model_override
        hook_called = True
        return original(
            self, model, api_key, base_url, max_tokens, temperature, custom_llm_provider
        )

    original = LlmApiManager.__init__
    LlmApiManager.__init__ = hook
    try:
        mod = importlib.import_module(module)
        mod = importlib.reload(mod)
    except ImportError:
        raise ValueError(f"Could not import module {module}")
    finally:
        LlmApiManager.__init__ = original

    if not hook_called:
        raise ShouldSkipError(f"Model override {model_override} not applied")

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


if __name__ == "__main__":
    conftest_path = Path(__file__).parent / "tests" / "conftest.py"

    # Run tests within this file
    extra_args = [str(Path(__file__))]
    pytest.main(sys.argv[1:] + extra_args)
