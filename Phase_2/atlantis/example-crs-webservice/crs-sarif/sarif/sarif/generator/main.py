import json
import os
import re
from pathlib import Path
from typing import Literal

from loguru import logger

from sarif.context import init_context
from sarif.generator.c import TAXA_WHITELIST_C
from sarif.generator.c import _get_only_san_output as parse_c_sanitizer_output
from sarif.generator.c import generate_sarif_custom_c, generate_sarif_ossfuzz_c
from sarif.generator.java import TAXA_WHITLELIST_JAVA
from sarif.generator.java import _get_only_san_output as parse_java_sanitizer_output
from sarif.generator.java import generate_sarif_custom_java
from sarif.llm.graph.sarif import SarifFinalState as FinalState
from sarif.llm.graph.sarif import generate_sarif_graph
from sarif.llm.graph.vuln_info import InputState as InitialState
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema,
    ArtifactLocation,
    Location,
    LogicalLocation,
    Message,
    Message1,
    MultiformatMessageString,
    PhysicalLocation,
    PhysicalLocation2,
    Region,
    Region1,
    ReportingDescriptor,
    ReportingDescriptorReference,
    ReportingDescriptorReference1,
    ReportingDescriptorReference3,
    Result,
    Run,
    Tool,
    ToolComponent,
    ToolComponentReference,
)
from sarif.validator.preprocess.format_validate import validate_format_multitool


def _load_taxonomies(language: Literal["c", "java"]) -> dict:
    from importlib.resources import files

    taxa_file_path = files("sarif.static") / "CWE_v4.8.sarif"
    taxonomies = json.loads(taxa_file_path.read_text())["runs"][0]["taxonomies"]
    all_taxa = taxonomies[0]["taxa"]

    if language == "c":
        taxa_whitelist = TAXA_WHITELIST_C.keys()
    elif language == "java":
        taxa_whitelist = TAXA_WHITLELIST_JAVA.keys()

    filtered_taxa = [taxa for taxa in all_taxa if taxa["id"] in taxa_whitelist]

    for taxa in filtered_taxa:
        if "relationships" in taxa:
            del taxa["relationships"]

    taxonomies[0]["taxa"] = filtered_taxa

    return taxonomies


def _run_llm(
    crash_log_path: Path,
    patch_diff_path: Path,
    language: Literal["c", "java"],
) -> FinalState:
    with open(crash_log_path, "r") as f:
        crash_log = f.read()

    sanitizer_output = (
        parse_c_sanitizer_output(crash_log)
        if language == "c"
        else parse_java_sanitizer_output(crash_log)
    )

    if patch_diff_path is not None:
        with open(patch_diff_path, "r") as f:
            patch_diff = f.read()
    else:
        patch_diff = ""

    # make out dir
    base_out_dir = Path(os.environ.get("DATA_DIR")) / language / "out"

    cpv_id = crash_log_path.stem.split(".")[0]
    out_dir = base_out_dir / cpv_id
    if not out_dir.exists():
        out_dir.mkdir(parents=True)

    init_context(src_dir="", out_dir=str(out_dir.resolve()))

    input_state = InitialState(
        package_language=language,
        package_name=cpv_id.split("_")[0],
        package_location="",
        vuln_id=cpv_id,
        sanitizer_output=sanitizer_output,
        patch_diff=patch_diff,
        experiment_name="Sarif generation",
    )

    sarif_graph = generate_sarif_graph()

    output = sarif_graph.invoke(input_state)

    return FinalState(**output)


def _update_taxa(
    sarif_report: AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema,
    llm_res: FinalState,
    language: Literal["c", "java"],
) -> AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema:
    taxonomies = _load_taxonomies(language)

    sarif_report.runs[0].taxonomies = taxonomies

    cwe_id_match = re.search(r"CWE-(\d+)", llm_res.vuln_type)
    cwe_id = cwe_id_match.group(0) if cwe_id_match else None

    tool_component = ToolComponentReference(name="CWE V4.8")
    reporting_1 = ReportingDescriptorReference3(id=cwe_id, toolComponent=tool_component)
    reporting = ReportingDescriptorReference(root=reporting_1)

    sarif_report.runs[0].results[0].taxa = [reporting]

    return sarif_report


def _update_related_locations(
    sarif_report: AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema,
    llm_res: FinalState,
) -> AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema:
    related_loc = llm_res.related_location

    for crash_loc in llm_res.crash_stack_trace:
        if (
            crash_loc.file_name == related_loc.file_name
            and crash_loc.line_number == related_loc.line_number
        ):
            logger.debug(
                "Crash location and related location are the same. Do not add related_location."
            )
            return sarif_report

    physical_location = PhysicalLocation(
        root=PhysicalLocation2(
            artifactLocation=ArtifactLocation(uri=related_loc.file_name),
            region=Region(root=Region1(startLine=related_loc.line_number)),
        )
    )

    logical_location = LogicalLocation(name=related_loc.function_name, kind="function")
    rel_loc = Location(
        physicalLocation=physical_location,
        logicalLocations=[logical_location],
        message=Message(root=Message1(text=related_loc.message)),
    )

    sarif_report.runs[0].results[0].relatedLocations = [rel_loc]

    return sarif_report


def _upgrade_sarif_using_llm(
    sarif_report: AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema,
    crash_log_path: Path,
    patch_diff_path: Path,
    language: Literal["c", "java"],
) -> AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema:
    llm_res = _run_llm(crash_log_path, patch_diff_path, language)

    # 1. Update taxa
    # https://github.com/microsoft/sarif-tutorials/blob/main/samples/3-Beyond-basics/standard-taxonomy.sarif
    _update_taxa(sarif_report, llm_res, language)

    # 2. Update relatedLocations
    # https://github.com/microsoft/sarif-tutorials/blob/main/samples/3-Beyond-basics/bad-eval-related-locations.sarif
    _update_related_locations(sarif_report, llm_res)

    # 3. Update stacks or codeflows
    # https://github.com/microsoft/sarif-tutorials/blob/main/samples/ResultStacks.sarif
    # https://github.com/microsoft/sarif-tutorials/blob/main/samples/3-Beyond-basics/bad-eval-with-code-flow.sarif
    # TODO

    return sarif_report


def generate_sarif(
    crash_log_path: Path,
    patch_diff_path: Path | None = None,
    language: Literal["c", "java"] | None = None,
    mode: Literal["custom", "ossfuzz"] = "custom",
    llm_on: bool = False,
    validate: bool = True,
    target_name: str | None = None,
) -> AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema:
    assert mode in ["custom", "ossfuzz"], "Invalid mode"

    if language is None:
        with open(crash_log_path, "r") as f:
            crash_log = f.read()

        logger.debug(
            "Language not provided. Trying to detect language from the crash log."
        )

        if (
            "== Java Exception: " in crash_log
            or "com.code_intelligence.jazzer" in crash_log
        ):
            language = "java"
            logger.debug("Detected language: Java")
        else:
            language = "c"
            logger.debug("Detected language: C")

    if mode == "custom":
        if language == "java":
            report = generate_sarif_custom_java(crash_log_path)
        else:
            report = generate_sarif_custom_c(crash_log_path)
    else:
        assert target_name is not None, "target_name is required for ossfuzz mode."
        assert language != "java", "Java is not supported in ossfuzz mode."

        report = generate_sarif_ossfuzz_c(crash_log_path, target_name)

    if report is None:
        raise ValueError("Error: SARIF log creation failed.")

    # Generate description using LLM
    if llm_on:
        report = _upgrade_sarif_using_llm(
            report, crash_log_path, patch_diff_path, language
        )

    if validate:
        tmp_path = Path("/tmp/tmp.sarif")
        save_sarif_to_file(report, tmp_path)
        validate_res = validate_format_multitool(tmp_path)
        os.remove(tmp_path)

    return report


def save_sarif_to_file(
    sarif_log: AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema | dict,
    filename: Path,
):
    if isinstance(sarif_log, dict):
        sarif_json = json.dumps(sarif_log, indent=2)
    elif isinstance(
        sarif_log, AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema
    ):
        sarif_json = sarif_log.model_dump_json(
            indent=2, exclude_none=True, exclude_defaults=True
        )  # Pretty-printed JSON
    else:
        assert False, "Invalid SARIF log type"

    # Write JSON to a file
    with open(filename, "w") as file:
        file.write(sarif_json)

    return


def parse_patch_diff_for_locations(
    patch_content: str,
) -> tuple[str | None, list[tuple[int, int]]]:
    """Parses unified diff format to find the file path and all hunk locations (start_line, end_line)."""
    file_path = None
    locations = []

    # Find the file path first
    file_match = re.search(r"^\+\+\+ b/(.*?)(?:\s+.*)?$", patch_content, re.MULTILINE)
    if file_match:
        file_path = file_match.group(1)
    else:
        return None, []  # No file path found

    # Find all hunk headers for the given file
    # Regex: ^@@ -old_start,old_count +new_start,new_count @@
    hunk_matches = re.finditer(
        r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", patch_content, re.MULTILINE
    )

    for match in hunk_matches:
        start_line_str = match.group(1)
        count_str = match.group(2)

        start_line = int(start_line_str)
        # If count is missing, it defaults to 1
        count = int(count_str) if count_str else 1

        # Only include hunks that have lines in the new file (count > 0)
        # A region must have endLine >= startLine
        if count > 0:
            end_line = start_line + count - 1
            locations.append((start_line, end_line))

    return file_path, locations


def generate_sarif_from_patch(
    patch_diff_path: Path,
) -> AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema:
    """
    Generates a SARIF report based on a patch diff file.
    Includes locations for all changed hunks detected in the diff.
    This function does not use LLM capabilities.
    """
    logger.info(f"Generating SARIF from patch diff: {patch_diff_path}")

    try:
        with open(patch_diff_path, "r") as f:
            patch_content = f.read()
    except Exception as e:
        logger.error(f"Failed to read patch diff file {patch_diff_path}: {e}")
        raise

    file_path, hunk_locations = parse_patch_diff_for_locations(patch_content)

    if file_path is None:
        raise ValueError(
            f"Could not parse file path from patch diff: {patch_diff_path}"
        )
    if not hunk_locations:
        logger.warning(
            f"Could not parse any valid hunk locations from patch diff {patch_diff_path}. SARIF report may lack specific locations."
        )
        # Decide if this should be an error or proceed with no specific location

    # Basic Tool definition (remains the same)
    tool = Tool(
        driver=ToolComponent(
            name="PatchAnalyzer",
            informationUri="http://example.com/patch-analyzer",  # Placeholder URI
            rules=[
                ReportingDescriptor(
                    id="PATCH001",
                    shortDescription=MultiformatMessageString(
                        text="Code Change Detected"
                    ),
                    helpUri="http://example.com/patch-analyzer/rules/PATCH001",  # Placeholder URI
                    properties={"category": "Code Change"},
                )
            ],
        )
    )

    # Create Location objects for each hunk
    locations = []
    artifact_location = ArtifactLocation(uri=file_path)
    for start_line, end_line in hunk_locations:
        region = Region(root=Region1(startLine=start_line, endLine=end_line))
        physical_location = PhysicalLocation(
            root=PhysicalLocation2(
                artifactLocation=artifact_location,  # Reference the same artifactLocation
                region=region,
            )
        )
        locations.append(Location(physicalLocation=physical_location))

    # If no specific hunk locations were found, create a location with just the file path
    if not locations and file_path:
        logger.info(f"Creating SARIF location with only file path for {file_path}")
        physical_location = PhysicalLocation(
            root=PhysicalLocation2(artifactLocation=artifact_location)
        )
        locations.append(Location(physicalLocation=physical_location))

    # Create Result
    result_message = f"Code changes detected in {file_path}"
    if not hunk_locations:
        result_message += " (Specific hunk locations not identified)"

    result = Result(
        ruleId="PATCH001",
        ruleIndex=0,
        level="note",
        message=Message(root=Message1(text=result_message)),
        locations=locations,  # Add all locations found
    )

    # Create Run
    run = Run(tool=tool, results=[result])

    # Create SARIF Report
    report = AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema(
        version="2.1.0", runs=[run]
    )

    return report
