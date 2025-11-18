import re
from pathlib import Path

from clusterfuzz import stacktraces
from loguru import logger

from sarif.context import SarifLLMManager
from sarif.llm.chat.base import BaseLLM, ask
from sarif.llm.chat.openai import GPT4oLLM
from sarif.llm.prompt.vuln_info import ParsedStackTraceModel, ParseStackTracePrompt
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema,
    ArtifactLocation,
    Invocation,
    Level,
    Location,
    LogicalLocation,
    Message,
    PhysicalLocation,
    Region,
    Result,
    Run,
    Tool,
    ToolComponent,
    Version,
)
from sarif.utils.datetime import creation_date
from sarif.utils.ossfuzz import SARIF_RULES, get_error_source_info, get_sarif_data

TAXA_WHITELIST_C = {
    "CWE-125": "Out-of-bounds Read",
    "CWE-787": "Out-of-bounds Write",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-416": "Use After Free",
    "CWE-415": "Double Free",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-190": "Integer Overflow or Wraparound",
}


def _remove_ansi(text):
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


def _get_only_san_output(crash_log: str):
    if not crash_log:
        return False

    if "\r\n" in crash_log:
        full_lines = crash_log.split("\r\n")
    else:
        full_lines = crash_log.split("\n")

    # Get the sanitizer output
    start_res = [r"runtime error:", r"ERROR: .+Sanitizer:", r"ERROR: libFuzzer:"]
    end_res = [
        r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in.+",
        r"SUMMARY: .+Sanitizer:",
        r"SUMMARY: libFuzzer: timeout",
    ]

    start_line = None
    end_line = None

    for idx, line in enumerate(full_lines):
        if start_line == None and any(
            [re.search(start_re, line) for start_re in start_res]
        ):
            start_line = idx
        elif any([re.search(end_re, line) for end_re in end_res]):
            end_line = idx + 1

    if start_line is None or end_line is None:
        return False

    return _remove_ansi("\n".join(full_lines[start_line:end_line]))


def _get_location_info(
    log: str, message: str | None = None, project_name: str | None = None
) -> Location:
    function = ""
    file_path = ""
    start_line = -1
    start_column = 1

    stack_parser = stacktraces.StackParser(
        symbolized=True,
        detect_ooms_and_hangs=True,
        include_ubsan=True,
    )
    crash_info = stack_parser.parse(log)
    error_source_info = get_error_source_info(crash_info)
    ossfuzz_uri = error_source_info[0]
    ossfuzz_line = error_source_info[1]

    for line in log.strip().split("\n"):
        if "asan" in line:
            continue

        stack_match = re.search(
            r"#\d 0x[\da-f]+ in (?P<function>\w+) (?P<file>.+):(?P<line>\d+):(?P<column>\d+)",
            line,
        )

        ossfuzz_match = f"{ossfuzz_uri}:{ossfuzz_line}" in line

        if ossfuzz_match and not stack_match:
            stack_match = re.search(
                r"#\d 0x[\da-f]+ in (?P<function>\w+) (?P<file>.+):(?P<line>\d+)",
                line,
            )

        if stack_match and ossfuzz_match:
            function = stack_match.group("function")
            file_path = stack_match.group("file")
            start_line = int(stack_match.group("line"))
            try:
                start_column = int(stack_match.group("column"))
            except IndexError:
                pass
            break

    if function == "" or file_path == "" or start_line == -1:
        logger.warning(f"Error getting location with regex")
        logger.info(f"Try to get location with LLM")

        # Fallback strategy (LLM)
        temperature = SarifLLMManager().temperature
        llm: BaseLLM = GPT4oLLM(temperature=temperature.default)

        res: ParsedStackTraceModel = ask(
            llm,
            ParseStackTracePrompt,
            {
                "crash_log": _get_only_san_output(log),
                "message": message,
                "project_name": project_name,
            },
            thread=[],
        )

        top_trace = res.stack_trace[0]

        file_path = top_trace.file_name
        function = top_trace.function_name
        start_line = top_trace.line_number
        start_column = top_trace.column_number

    if start_line == -1 or start_line == 0:
        logger.warning(f"Error getting line number")
        start_line = None

    if start_column == -1:
        logger.warning(f"Error getting column number")
        start_column = None

    physical_location = PhysicalLocation(
        artifactLocation=ArtifactLocation(uri=file_path),
        region=Region(startLine=start_line, startColumn=start_column),
    )

    logical_location = LogicalLocation(name=function, kind="function")
    location = Location(
        physicalLocation=physical_location,  # Use the correct alias and ensure the input matches the schema
        logicalLocations=[logical_location],
    )

    return location


def generate_sarif_custom_c(
    log_path: Path,
) -> AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema:
    with open(log_path, "r") as file:
        log = file.read()

    infered_project_name = log_path.stem.split("-")[0].split("_")[0]

    # SARIF version and schema, use 2.1.0
    version = Version.field_2_1_0
    schema = "http://json-schema.org/draft-04/schema#"

    # Detection tool information, name and rules encoded, etc
    tool_driver = ToolComponent(
        name="Atlantis", version="1.0.0", rules=SARIF_RULES  # Add any rules if needed
    )
    tool = Tool(driver=tool_driver)

    # Detection tool invocation information, skip for now

    # Artifact: target program information
    creation_time = creation_date(log_path)
    invocation = Invocation(
        commandLine="",
        executionSuccessful=True,  # Set executionSuccessful to True
        startTimeUtc=creation_time,
    )

    # Results: rule id
    # TODO: Fix "attempting" case
    # TODO: ==14==ERROR: AddressSanitizer: attempting double-free on 0x506000006d40 in thread T0:
    rule_id = ""
    rule_id_match = re.search(r"==\d+==ERROR: ([^:]+): (.+)", log)
    if rule_id_match and rule_id_match.group(2):
        rule_id = rule_id_match.group(2).split()[0].strip()

    # Results: message
    message_text = ""
    message_text_match = re.search(r"SUMMARY: (.*?)\n", log)
    if message_text_match:
        error_message = message_text_match.group(1)
        message_text = error_message
    result_message = Message(text=message_text)

    # Results: location
    location = _get_location_info(
        log, message=message_text, project_name=infered_project_name
    )

    # Create a result
    result = Result(
        ruleId=rule_id, level=Level.error, message=result_message, locations=[location]
    )

    # Create a run
    run = Run(
        tool=tool,
        results=[result],
        invocations=[invocation],
    )

    # Create the SARIF log
    sarif_log = AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema(
        version=Version.field_2_1_0, runs=[run]
    )

    return sarif_log


def generate_sarif_ossfuzz_c(log_path: Path, target_name: str) -> dict:
    with open(log_path, "r") as file:
        log = file.read()

    res = get_sarif_data(log, target_name)

    return res
