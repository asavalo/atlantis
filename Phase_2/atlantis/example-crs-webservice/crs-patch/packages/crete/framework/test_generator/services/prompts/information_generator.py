import inspect

from .json_format import TEST_SCRIPT_JSON_FORMAT

# INFORMATION GENERATOR

TEST_INFO_SYSTEM_PROMPT = (
    "You are a helpful assistant that analyzes project test information."
)

TEST_INFO_PROMPT = inspect.cleandoc(
    """
Based on the following project information, please extract and summarize ONLY public test-related information.
For each piece of information you extract, please indicate its source by looking at the "=== File: filename.txt ===" headers in the project information.
Add the source in parentheses like this: (by filename.txt).

By "public test", I mean the project's built-in tests that verify the functionality of the project's binaries or libraries - NOT fuzzing tests.
Examples of public tests include:
- Unit tests (pytest, JUnit, googletest, etc.)
- Integration tests 
- System tests
- Commands like: mvn test, gradle test, pytest, make test, npm test, go test, cargo test, etc.

Please focus ONLY on:
1. Public test framework and requirements (e.g., JUnit, pytest, googletest)
2. Public test dependencies and their versions
3. Public test execution steps and commands (e.g., mvn test, make test, pytest)
4. Public test environment setup requirements
5. Public test configuration
6. Public test reports and output formats

IMPORTANT GUIDELINES:
- For each question/topic above, provide a detailed answer of 3-5 lines. One-line answers are insufficient.
- Each answer should be comprehensive yet concise, covering key details in 3-5 lines.
- EMPHASIZE BUILD AND TEST COMMANDS: Highlight specific commands like 'make test', 'npm test', 'pytest', etc. These are the most important information.
- COMPLETELY EXCLUDE DIRECTORY LISTINGS: DO NOT include ANY information from DirectoryStructure.txt in your summary.
- Focus on actionable information that would help in creating test scripts, especially build and test commands.
- DO NOT include information about fuzzing tests or fuzz targets.

Project Information:
{project_info}
"""
)


ERROR_FIX_MANUAL = inspect.cleandoc(
    """
## Error Fix Manual(For Reference Only) :
- "make: *** No targets specified and no makefile found.":
  - Potential Fix: Ensure you are in the correct directory. Try running `cd /out/src && ../configure` or verify the presence of a Makefile using `ls`.
- "Error: Could not find a valid GEM_HOME environment variable":
  - Potential Fix: Set the GEM_HOME variable or install Bundler with `gem install bundler`.
- "npm: command not found":
  - Potential Fix: Node.js is not installed. Install it using `apt update && apt install nodejs npm -y`.
"""
)


GENERATOR_JSON_OUTPUT_FORMAT = f"""## JSON Output Format:
Your response MUST be a valid JSON object with exactly these keys:
{TEST_SCRIPT_JSON_FORMAT}
Do not include any text outside of the JSON object. Do not include markdown formatting like ```json or ``` around your response."""


TEST_RESULT_SUMMARY = inspect.cleandoc(
    """
Include a summary of test results at the end in the following format:
TOTAL=$((SUCCESS_COUNT + FAIL_COUNT))
echo "=================================================="
echo "[INFO] Done building all modules!"
echo "[INFO] Success modules: $SUCCESS_COUNT"
echo "[INFO] Fail modules: $FAIL_COUNT"
echo "[INFO] Total modules processed: $TOTAL"
echo "=================================================="
echo "[INFO] Successful modules:"
echo " - <module1>"
echo "[INFO] Failed modules:"
echo " - <module2>"
"""
)
