import argparse
from pathlib import Path

from fuzz_introspector.analysis import AnalysisInterface, IntrospectionProject
from loguru import logger

from sarif.tools.introspector.core import _analyse_end_to_end

# SINKS = cwe_data.SINK_FUNCTION
# CWES = list(SINKS)


def run_sink_analysis(
    language: str,
    target_dir: Path,
    out_dir: Path,
    harness_paths: list[str] | None = None,
    output: Path | None = None,
):
    introspector_project: IntrospectionProject = _analyse_end_to_end(
        oss_fuzz_lang=language,
        target_dir=target_dir,
        out_dir=out_dir,
        harness_paths=harness_paths,
        analyses_to_run=["SinkCoverageAnalyser"],
    )

    analysis_instance: AnalysisInterface = introspector_project.optional_analyses[0]

    print(analysis_instance.get_json_string_result())

    if output is None:
        output = out_dir / "sink_analysis.json"

    with open(output, "w") as f:
        f.write(analysis_instance.get_json_string_result())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--language",
        type=str,
        choices=["c", "cpp", "java"],
        default="c",
        help="Target programming language (default: c)",
    )
    parser.add_argument(
        "--target-dir", type=Path, required=True, help="Path to target directory"
    )
    parser.add_argument(
        "--harness-paths",
        type=str,
        nargs="+",
        required=False,
        help="Path to harness files",
        default=None,
    )
    parser.add_argument(
        "--out-dir", type=Path, required=True, help="Path to output directory"
    )
    parser.add_argument(
        "--output", type=Path, required=False, help="Path to output file"
    )
    args = parser.parse_args()

    run_sink_analysis(
        language=args.language,
        target_dir=args.target_dir,
        out_dir=args.out_dir,
        harness_paths=args.harness_paths,
        output=args.output,
    )
