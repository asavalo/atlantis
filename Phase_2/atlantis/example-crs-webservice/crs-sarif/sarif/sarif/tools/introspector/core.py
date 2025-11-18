from pathlib import Path
from typing import Literal

from fuzz_introspector import constants as introspector_constants
from fuzz_introspector import html_report
from fuzz_introspector.analysis import IntrospectionProject, get_all_analyses
from fuzz_introspector.exceptions import DataLoaderError
from fuzz_introspector.frontends import oss_fuzz
from loguru import logger


def _analyse_end_to_end(
    oss_fuzz_lang: Literal["c", "cpp", "jvm"],
    target_dir: Path,
    out_dir: Path,
    harness_paths: list[str] | None = None,
    analyses_to_run: list[str] | None = None,
) -> IntrospectionProject:

    if oss_fuzz_lang == "jvm":
        entrypoint = "fuzzerTestOneInput"
    else:
        entrypoint = "LLVMFuzzerTestOneInput"

    if harness_paths is None:
        harness_paths = []

    return_values = {}
    # project, _ = oss_fuzz.analyse_folder(
    # harness_lists is always None....
    project, harness_lists = oss_fuzz.analyse_folder(
        language=oss_fuzz_lang,
        directory=target_dir.as_posix(),
        entrypoint=entrypoint,
        out=out_dir.as_posix(),
        files_to_include=harness_paths,
    )

    if oss_fuzz_lang == "c" or oss_fuzz_lang == "cpp":
        oss_fuzz_lang = "c-cpp"

    if harness_lists:
        logger.info("We have a harness list")
    else:
        logger.info("No harness list at place")

    return_values["light-project"] = project

    correlation_file = out_dir / "exe_to_fuzz_introspector_logs.yaml"
    if not correlation_file.is_file():
        correlation_file = ""
    else:
        correlation_file = correlation_file.as_posix()

    try:
        introspector_project = _run_analysis_on_dir(
            language=oss_fuzz_lang,
            target_folder=out_dir,
            analyses_to_run=analyses_to_run,
            correlation_file=correlation_file,
            enable_all_analyses=True if analyses_to_run is None else False,
            out_dir=out_dir,
            harness_lists=harness_lists,
        )
    except DataLoaderError as e:
        logger.info("Found data issues. Exiting gracefully.")
        raise e

    return introspector_project


def _run_analysis_on_dir(
    language: Literal["c", "cpp", "jvm"],
    target_folder: Path,
    analyses_to_run: list[str],
    correlation_file: Path | None,
    enable_all_analyses: bool,
    out_dir: Path,
    harness_lists=None,
) -> IntrospectionProject:
    logger.info("Running analysis")
    introspector_constants.should_dump_files = True

    if enable_all_analyses:
        for analysis_interface in get_all_analyses():
            if analysis_interface.get_name() not in analyses_to_run:
                analyses_to_run.append(analysis_interface.get_name())

    introspection_proj = IntrospectionProject(
        language, target_folder.as_posix(), "/covreport/linux"
    )
    introspection_proj.load_data_files(
        False, correlation_file, out_dir.as_posix(), harness_lists
    )

    output_json = []

    # TODO: Perform only reachability analysis??
    # html_report.create_html_report(
    #     introspection_proj,
    #     analyses_to_run,
    #     output_json,
    #     "introspector",
    #     True,
    #     out_dir=out_dir.as_posix(),
    # )

    return introspection_proj
