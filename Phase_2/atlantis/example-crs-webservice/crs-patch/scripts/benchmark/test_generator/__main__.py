import logging
from pathlib import Path
from typing import Optional

import click
from crete.framework.test_generator.functions import (
    get_project_names,
)
from crete.framework.test_generator.services.test_generator import generate_for_oss_fuzz
from python_llm.api.actors import LlmApiManager


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

# Log file will be in the same directory as this script
LOG_FILE = Path(__file__).parent / "benchmark_results.log"


def log_message(message: str, initialize: bool = False):
    """Log message to file and stdout"""
    mode = "w" if initialize else "a"
    with LOG_FILE.open(mode, encoding="utf-8") as f:
        f.write(f"{message}\n")
    print(message)


@click.command()
@click.option(
    "--projects",
    "-p",
    help="Comma-separated list of project names to benchmark",
    type=str,
    default=None,
)
@click.option(
    "--mode",
    type=click.Choice(["small", "big"]),
    default="small",
    help="Benchmark mode: 'small' for major projects only, 'big' for all OSS-Fuzz projects",
)
@click.option(
    "--llm-model",
    help="LLM model to use for main tasks (default: gpt-4o)",
    type=str,
    default="gpt-4o",
)
@click.option(
    "--formatter-model",
    help="LLM model to use for formatting (default: gpt-4o-mini)",
    type=str,
    default="gpt-4o-mini",
)
def main(
    projects: Optional[str] = None,
    mode: str = "small",
    llm_model: str = "gpt-4o",
    formatter_model: str = "gpt-4o-mini",
) -> None:
    """Run benchmark tests for test generation on OSS projects.

    This benchmark script evaluates the test generator's performance on open-source software projects.
    It attempts to build each project, generate test information, and create tests.

    Two modes are available:
    - small: Tests only the major projects (default)
    - big: Tests all OSS-Fuzz projects

    Results are logged to a file and displayed in the terminal.
    """
    # Get the list of projects to benchmark
    project_names = get_project_names(mode, projects)

    log_message("=== Test Generator Benchmark Started ===", initialize=True)
    log_message(f"Benchmark mode: {mode}")
    log_message(f"Running benchmark on {len(project_names)} projects")
    log_message(f"Using LLM model: {llm_model}")
    log_message(f"Using formatter model: {formatter_model}")
    log_message("=" * 50)

    project_num = 0
    build_success_project_num = 0
    test_success_project_num = 0

    llm_api_manager = LlmApiManager.from_environment(model=llm_model)
    llm_formatter_manager = LlmApiManager.from_environment(model=formatter_model)

    for project_name in project_names:
        project_num += 1
        log_message(f"\nProject {project_num}/{len(project_names)}: {project_name}")
        log_message("-" * 50)

        # Use the generate_for_oss_fuzz function
        build_success, test_success = generate_for_oss_fuzz(
            project_name,
            llm_api_manager,
            llm_formatter_manager,
            log_callback=log_message,
        )

        if build_success:
            build_success_project_num += 1

        if test_success:
            test_success_project_num += 1

    log_message("\n" + "=" * 50)
    log_message("=== Summary ===")
    log_message(f"Benchmark mode: {mode}")
    log_message(f"Total projects: {project_num}")

    # Calculate percentages safely
    build_success_percent = (
        (build_success_project_num / project_num * 100) if project_num > 0 else 0
    )
    test_success_percent = (
        (test_success_project_num / project_num * 100) if project_num > 0 else 0
    )

    log_message(
        f"Build success: {build_success_project_num}/{project_num} ({build_success_percent:.1f}%)"
    )
    log_message(
        f"Test success: {test_success_project_num}/{project_num} ({test_success_percent:.1f}%)"
    )
    log_message(f"Results saved to: {LOG_FILE}")
    log_message("=== End of Benchmark ===")


if __name__ == "__main__":
    main()
