import re
from pathlib import Path
from typing import Tuple

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

SARIF_RULES_JAVA = [
    {
        "id": "FuzzerSecurityIssueCritical: OS Command Injection",
        "shortDescription": {"text": "OS Command Injection."},
        "helpUri": "https://cwe.mitre.org/data/definitions/78.html",
    },
    {
        "id": "FuzzerSecurityIssueCritical: Integer Overflow",
        "shortDescription": {"text": "Integer Overflow."},
        "helpUri": "https://cwe.mitre.org/data/definitions/190.html",
    },
    {
        "id": "FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)",
        "shortDescription": {"text": "Server Side Request Forgery (SSRF)."},
        "helpUri": "https://cwe.mitre.org/data/definitions/918.html",
    },
    {
        "id": "FuzzerSecurityIssueHigh: Remote Code Execution",
        "shortDescription": {"text": "Remote Code Execution."},
        # TODO: map to CWE (CWE-94???)
        "helpUri": "https://cwe.mitre.org/data/definitions/94.html",
    },
    {
        "id": "FuzzerSecurityIssueHigh: SQL Injection",
        "shortDescription": {"text": "SQL Injection."},
        "helpUri": "https://cwe.mitre.org/data/definitions/89.html",
    },
    {
        "id": "FuzzerSecurityIssueCritical: Remote JNDI Lookup",
        "shortDescription": {"text": "Remote JNDI Lookup."},
        # TODO: map to CWE (CWE-502???)
        "helpUri": "https://cwe.mitre.org/data/definitions/502.html",
    },
    {
        "id": "FuzzerSecurityIssueCritical: LDAP Injection",
        "shortDescription": {"text": "LDAP Injection."},
        "helpUri": "https://cwe.mitre.org/data/definitions/90.html",
    },
    {
        "id": "FuzzerSecurityIssueHigh: XPath Injection",
        "shortDescription": {"text": "XPath Injection."},
        "helpUri": "https://cwe.mitre.org/data/definitions/643.html",
    },
    {
        "id": "FuzzerSecurityIssueHigh: load arbitrary library",
        "shortDescription": {"text": "load arbitrary library."},
        # TODO: map to CWE (No idea)
        "helpUri": "https://cwe.mitre.org/data/definitions/",
    },
    {
        "id": "FuzzerSecurityIssueLow: Regular Expression Injection",
        "shortDescription": {"text": "Regular Expression Injection."},
        # TODO: map to CWE (CWE-777????)
        "helpUri": "https://cwe.mitre.org/data/definitions/777.html",
    },
    {
        "id": "FuzzerSecurityIssueCritical: Script Engine Injection",
        "shortDescription": {"text": "Script Engine Injection."},
        # TODO: map to CWE (CWE-94???)
        "helpUri": "https://cwe.mitre.org/data/definitions/94.html",
    },
    {
        "id": "FuzzerSecurityIssueCritical: File read/write hook path",
        "shortDescription": {"text": "File read/write hook path."},
        # TODO: map to CWE (CWE-22???)
        "helpUri": "https://cwe.mitre.org/data/definitions/22.html",
    },
]


TAXA_WHITLELIST_JAVA = {
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-77": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-90": "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
    "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-643": "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
    "CWE-777": "Regular Expression without Anchors",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}


def _get_only_san_output(log: str) -> str:
    """Returns only the sanitizer output from the log."""
    START_STR = "== Java Exception: "
    END_STR = "== libFuzzer crashing input =="

    start = log.find(START_STR)
    end = log.rfind(END_STR)

    if start == -1:
        START_STR = "ERROR: libFuzzer:"
        END_STR = "SUMMARY: libFuzzer: timeout"

        start = log.find(START_STR)
        end = log.rfind(END_STR)

        if start == -1:
            raise ValueError("No Java Exception found in the log.")

    if end == -1:
        return log[start:]
    else:
        return log[start : end + len(END_STR)]


def _get_rule_id_and_text(log: str) -> Tuple[str, str]:
    """Returns the rule id and message text from the log."""
    match = re.search(r"== Java Exception: ([^:]+): (.+)", log)
    if match:
        return match.group(1), match.group(2)

    return "", ""


def _get_location_info(
    log: str, message: str | None = None, project_name: str | None = None
) -> Location:
    function = ""
    file_path = ""
    start_line = -1
    start_column = 1

    # First, remove everything from the log until "== Java Exception: "
    stack_trace_log = _get_only_san_output(log)

    # Then, search for the stack frames
    stack_match = re.findall(
        r"\tat (?P<function>.+)\((?P<file>[^:]+):(?P<line>\d+)\)",
        stack_trace_log,
    )

    for match in stack_match:
        function, file_path, start_line = match

        if "code_intelligence.jazzer" in function or function.startswith("jaz.Zer."):
            continue

        if "/" in function or function.startswith("javax"):
            continue

        # TODO: Replace the following by filtering for packages that are in scope
        if (
            "org.mockito" in function
            or "org.springframework" in function
            or "org.apache.http" in function
        ):
            continue

        # TODO: enhance with details from CP (benchmark lib)

        break

    if function == "" or file_path == "" or start_line == -1:
        logger.error(f"Error getting location with regex")
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

    if start_line == -1:
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
        physicalLocation=physical_location,
        logicalLocations=[logical_location],
    )

    return location


def generate_sarif_custom_java(
    log_path: Path,
) -> AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema:
    with open(log_path, "r") as fptr:
        log = fptr.read()

    infered_project_name = log_path.stem.split("-")[0].split("_")[0]

    # SARIF version and schema, use 2.1.0
    version = Version.field_2_1_0
    schema = "http://json-schema.org/draft-04/schema#"

    # Results: rule id
    rule_id, message_text = _get_rule_id_and_text(log)
    result_message = Message(text=message_text)

    # Results: location
    location = _get_location_info(log, project_name=infered_project_name)

    # Create a result
    result = Result(
        ruleId=rule_id, level=Level.error, message=result_message, locations=[location]
    )

    # Artifact: target program information
    creation_time = creation_date(log_path)
    invocation = Invocation(
        commandLine="",
        executionSuccessful=True,  # Set executionSuccessful to True
        startTimeUtc=creation_time,
    )

    # Detection tool information, name and rules encoded, etc
    tool_driver = ToolComponent(
        name="Atlantis",
        version="1.0.0",
        rules=SARIF_RULES_JAVA,  # Add any rules if needed
    )
    tool = Tool(driver=tool_driver)

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
