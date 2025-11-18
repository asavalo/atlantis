from enum import Enum, auto
import argparse
import os
from loguru import logger
import json
from pathlib import Path
import typing
from typing import Generator
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema,
    Result,
    Location,
)
from sarif.matcher.crash_report import CrashReport, StackFrame
from sarif.matcher.coverage import Coverage


class SarifPovMatchingStrategy(Enum):
    STRICT = auto()

    DEFAULT = STRICT


def _is_location_matched(represented_location: str, sarif_location: str) -> bool:
    # NOTE: coverage file location is dwarf information,
    # Assumme that dwarf location includes sarif's source location
    return represented_location.endswith(sarif_location) or sarif_location.endswith(
        represented_location
    )


def get_physical_locations(
    result: Result,
) -> Generator[tuple[str, int, int], None, None]:
    locations = result.locations

    for location in locations:
        physical_location = location.physicalLocation.root
        # logger.info(json.dumps(physical_location.model_dump(), indent=2))

    for location in locations:
        if location.physicalLocation is None:
            continue
        physical_location = location.physicalLocation.root
        try:
            physical_location.artifactLocation.uri
            physical_location.region
        except AttributeError:
            continue

        uri = physical_location.artifactLocation.uri
        start_line = physical_location.region.root.startLine
        end_line = physical_location.region.root.endLine
        if end_line is None:
            end_line = start_line
        yield uri, start_line, end_line


def match_location_stacktrace(
    result: Result,
    crash: CrashReport,
    strategy: SarifPovMatchingStrategy,
) -> float:
    stacktrace = crash.stacktrace

    # logger.info(json.dumps([frame.model_dump() for frame in stacktrace], indent=2))

    for uri, start_line, end_line in get_physical_locations(result):
        for frame in stacktrace:
            if _is_location_matched(frame.filepath, uri) and (
                (
                    (end_line is None and start_line == frame.lineno)
                    or (
                        end_line is not None
                        and start_line <= frame.lineno
                        and end_line >= frame.lineno
                    )
                )
            ):
                logger.info(
                    f"Found stackframe({frame.filepath}:{frame.lineno}) in result"
                )
                return 1.0

    # logger.info("No stackframe matched in result")
    return 0.0


def match_result_pov(
    result: Result,
    crash: CrashReport,
    strategy: SarifPovMatchingStrategy,
) -> float:
    # logger.info(f"Sarif RuleID: {result.ruleId}")
    # logger.info(f"Crash RuleID: {crash.rule_id}")
    if result.ruleId != crash.rule_id:
        logger.info("RuleID mismatch")
        return 0.0
    else:
        logger.info(f"RuleID matched")
        return match_location_stacktrace(result, crash, strategy)


def match_sarif_coverage(
    sarif: AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema,
    coverage: Coverage,
) -> float:
    results = [result for run in sarif.runs for result in run.results]
    total_lines = 0
    matched_lines = 0

    for result in results:
        for uri, start_line, end_line in get_physical_locations(result):
            total_lines += end_line - start_line + 1

            for covered_file in coverage.files:
                if not _is_location_matched(covered_file.src, uri):
                    continue

                for lineno in covered_file.lines:
                    if start_line <= lineno and lineno <= end_line:
                        matched_lines += 1

    return matched_lines / total_lines


def match_sarif_pov(
    sarif: AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema,
    crash: CrashReport,
    strategy: SarifPovMatchingStrategy = SarifPovMatchingStrategy.DEFAULT,
) -> float:
    results = [result for run in sarif.runs for result in run.results]
    match_probs = [match_result_pov(result, crash, strategy) for result in results]
    logger.info(f"Match probabilities: {match_probs}")
    return max(match_probs) if match_probs else 0.0


# Helper function to parse unified diff format
def _parse_patch_lines(patch_content: str) -> typing.Dict[str, set[int]]:
    """Parses a unified diff and returns a dict mapping file paths to sets of added line numbers."""
    lines_by_file: typing.Dict[str, set[int]] = {}
    current_file: str | None = None
    current_line_in_hunk: int = 0

    for line in patch_content.splitlines():
        if line.startswith("+++ "):
            path_part = line[4:].split("	")[0]  # Handle potential timestamp
            # Heuristic to strip prefixes like 'a/' or 'b/'
            if path_part.startswith("b/"):
                current_file = path_part[2:]
            elif path_part.startswith("a/"):
                current_file = path_part[2:]
            else:
                current_file = path_part
            if current_file is not None and current_file not in lines_by_file:
                lines_by_file[current_file] = set()
            # Reset line counter, wait for @@ line
            current_line_in_hunk = 0

        elif line.startswith("@@"):
            try:
                # Example: @@ -15,6 +15,7 @@ -> parse "+15,7"
                new_range_part = line.split(" ")[2]
                if "," in new_range_part:
                    new_start_line = int(new_range_part.split(",")[0][1:])
                else:  # Handle case like "+15" (means count is 1)
                    new_start_line = int(new_range_part[1:])
                current_line_in_hunk = (
                    new_start_line  # Start counting from here in the new file
                )
            except (IndexError, ValueError) as e:
                logger.warning(f"Could not parse hunk header: {line} - {e}")
                current_line_in_hunk = 0  # Reset on error

        elif (
            line.startswith("+")
            and not line.startswith("+++")
            and current_file is not None
        ):
            if (
                current_line_in_hunk > 0
            ):  # Make sure we have a valid line number from @@
                lines_by_file[current_file].add(current_line_in_hunk)
                current_line_in_hunk += 1  # Increment for the next line (added/context)
            else:
                # Log if an added line appears without preceding hunk info
                logger.warning(
                    f"Found added line without valid hunk context: {line} in file {current_file}"
                )

        elif line.startswith(" ") and current_file is not None:
            if current_line_in_hunk > 0:
                current_line_in_hunk += (
                    1  # Context lines also advance the line number in the new file
                )

        elif line.startswith("-") and not line.startswith("---"):
            # Removed lines do not advance the line number in the *new* file state
            pass

    return lines_by_file


# Helper function to extract lines from SARIF
def _extract_sarif_lines(
    sarif: AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema,
) -> typing.Dict[str, set[int]]:
    """Extracts file paths and line numbers from SARIF results."""
    lines_by_file: typing.Dict[str, set[int]] = {}
    for run in sarif.runs:
        if run.results is None:
            continue
        for result in run.results:
            if result.locations is None:
                continue
            for location in result.locations:
                # Use getattr for safer access to potentially missing attributes
                physical_loc = getattr(location, "physicalLocation", None)
                physical_loc = getattr(physical_loc, "root", None)
                artifact_loc = getattr(physical_loc, "artifactLocation", None)
                region = getattr(physical_loc, "region", None)
                region = getattr(region, "root", None)
                uri = getattr(artifact_loc, "uri", None)

                # Get line numbers, default endLine to startLine if missing
                start_line = getattr(region, "startLine", None)
                end_line = getattr(
                    region, "endLine", start_line
                )  # Use start_line if endLine is None
                end_line = start_line if end_line is None else end_line

                if uri is not None and start_line is not None and end_line is not None:
                    file_path = uri

                    if file_path not in lines_by_file:
                        lines_by_file[file_path] = set()

                    try:
                        # Ensure lines are positive integers before adding range
                        start_line_int = int(start_line)
                        end_line_int = int(end_line)
                        if start_line_int > 0 and end_line_int >= start_line_int:
                            for line_num in range(start_line_int, end_line_int + 1):
                                lines_by_file[file_path].add(line_num)
                        else:
                            logger.warning(
                                f"Invalid line range in SARIF: file={file_path}, start={start_line}, end={end_line}"
                            )
                    except ValueError:
                        logger.warning(
                            f"Non-integer line number in SARIF: file={file_path}, start={start_line}, end={end_line}"
                        )

    return lines_by_file


def match_sarif_patch(
    sarif: AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema,
    patch_content: str,
) -> tuple[int, int, int]:
    """
    Calculates the overlap between SARIF result locations and lines added in a patch content string.

    Args:
        sarif: The SARIF report object.
        patch_content: The content of the patch file in unified diff format.

    Returns:
        A tuple: (lines_only_in_sarif, lines_in_both, lines_only_in_patch)
    """
    # Parse patch and SARIF to get line sets per file
    patch_lines_by_file = _parse_patch_lines(patch_content)
    sarif_lines_by_file = _extract_sarif_lines(sarif)

    # logger.info(f"Patch Content: {patch_content}")
    logger.info(f"Patch lines by file: {patch_lines_by_file}")
    logger.info(f"SARIF lines by file: {sarif_lines_by_file}")

    # Calculate overlap counts across all relevant files
    total_sarif_only = 0
    total_common = 0
    total_patch_only = 0

    for patch_file in patch_lines_by_file:
        patch_lines = patch_lines_by_file.get(patch_file, set())
        sarif_lines = set()
        for sarif_file in sarif_lines_by_file:
            if _is_location_matched(patch_file, sarif_file):
                sarif_lines |= sarif_lines_by_file.get(sarif_file, set())

        # Calculate counts for the current file
        current_sarif_only = len(sarif_lines - patch_lines)
        current_common = len(sarif_lines & patch_lines)
        current_patch_only = len(patch_lines - sarif_lines)

        # Log detailed comparison if needed
        if sarif_lines or patch_lines:
            logger.info(f"Comparing file: {patch_file}")
            logger.info(
                f"  SARIF lines ({len(sarif_lines)}): {sorted(list(sarif_lines))[:10]}..."
            )
            logger.info(
                f"  Patch lines ({len(patch_lines)}): {sorted(list(patch_lines))[:10]}..."
            )
            logger.info(
                f"  Counts: SarifOnly={current_sarif_only}, Common={current_common}, PatchOnly={current_patch_only}"
            )

        # Aggregate counts
        total_sarif_only += current_sarif_only
        total_common += current_common
        total_patch_only += current_patch_only

    logger.info(
        f"Total counts: SarifOnly={total_sarif_only}, Common={total_common}, PatchOnly={total_patch_only}"
    )

    if total_sarif_only + total_common + total_patch_only == 0:
        return 0.0

    return total_common / (total_sarif_only + total_common + total_patch_only)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SARIF Matcher")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subparser for pov-sarif matching
    parser_pov = subparsers.add_parser(
        "pov-sarif",
        help="Match a SARIF file against a crash log (Point of Vulnerability).",
    )
    parser_pov.add_argument(
        "-s",
        "--sarif",
        type=str,
        required=True,
        help="Path to the SARIF file",
    )
    parser_pov.add_argument(
        "-c",
        "--crash",
        type=str,
        required=True,
        help="Path to the crash log file",
    )
    parser_pov.add_argument(
        "-l",
        "--lang",
        type=str,
        required=True,
        choices=["c", "jvm"],
        help="Programming language of the crash log.",
    )
    parser_pov.add_argument(
        "--strategy",
        type=str,
        choices=["strict"],
        default="strict",
        help="Matching strategy for POV.",
    )

    # Subparser for patch-sarif matching
    parser_patch = subparsers.add_parser(
        "patch-sarif", help="Match a SARIF file against a patch diff."
    )
    parser_patch.add_argument(
        "-s",
        "--sarif",
        type=str,
        required=True,
        help="Path to the SARIF file",
    )
    parser_patch.add_argument(
        "-p",
        "--patch",
        type=str,
        required=True,
        help="Path to the patch diff file",
    )
    # Subparser for coverage-sarif matching
    parser_coverage = subparsers.add_parser(
        "coverage-sarif", help="Match a SARIF file against a coverage file."
    )
    parser_coverage.add_argument(
        "-c",
        "--coverage",
        type=str,
        required=True,
        help="Path to the coverage file",
    )
    parser_coverage.add_argument(
        "-s",
        "--sarif",
        type=str,
        required=True,
        help="Path to the SARIF file",
    )
    args = parser.parse_args()

    # Load SARIF file (common to both commands)
    try:
        with open(args.sarif, "r") as f:
            sarif_data = AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema.model_validate_json(
                f.read()
            )
    except Exception as e:
        print(f"Error reading SARIF file {args.sarif}: {e}")
        exit(-1)
    logger.info(f"Loaded SARIF: {args.sarif}")

    if args.command == "pov-sarif":
        match args.strategy:
            case "strict":
                strategy = SarifPovMatchingStrategy.STRICT
            case _:
                # This case should not be reachable due to choices constraint
                logger.warning(f"Unknown strategy: {args.strategy}")
                exit(-1)

        logger.info(f"Matching strategy: {args.strategy}")

        try:
            with open(args.crash, "r") as f:
                crash_data = CrashReport.from_bytes(f.read().encode("utf-8"), args.lang)
        except Exception as e:
            print(f"Error reading crash file {args.crash}: {e}")
            exit(-1)
        logger.info(f"Loaded Crash: {args.crash}")

        match_prob = match_sarif_pov(sarif_data, crash_data, strategy)
        logger.info(f"Match probability (SARIF <-> POV): {match_prob}")
        print(f"Match probability: {match_prob}")

    elif args.command == "patch-sarif":
        try:
            with open(args.patch, "r") as f:
                patch_content = f.read()
        except Exception as e:
            print(f"Error reading patch file {args.patch}: {e}")
            exit(-1)
        logger.info(f"Loaded Patch: {args.patch}")

        sarif_only, common, patch_only = match_sarif_patch(sarif_data, patch_content)
        logger.info(
            f"Match counts (SARIF <-> Patch): SarifOnly={sarif_only}, Common={common}, PatchOnly={patch_only}"
        )
        print(f"SarifOnly={sarif_only}, Common={common}, PatchOnly={patch_only}")

    elif args.command == "coverage-sarif":
        try:
            with open(args.coverage, "r") as f:
                coverage_data = Coverage.from_coverage_file(f.read())
        except Exception as e:
            print(f"Error reading coverage file {args.coverage}: {e}")
            exit(-1)
        logger.info(f"Loaded Coverage: {coverage_data.model_dump_json(indent=2)}")

        match_prob = match_sarif_coverage(sarif_data, coverage_data)
        logger.info(f"Match probability (SARIF <-> Coverage): {match_prob}")
        print(f"Match probability: {match_prob}")
