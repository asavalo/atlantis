import inspect

# from .json_format import JSON_FORMAT_INSTRUCTION, TEST_SCRIPT_JSON_FORMAT
# TEST GENERATOR

GENERATOR_SYSTEM_PROMPT = inspect.cleandoc(
    """
You are an AI assistant that fixes test scripts based on error logs.
If no error log is provided, generate a new test script using the available information.
If an error log is provided, analyze the error log and the previous test script, then generate a new test script that fixes the issues indicated in the error log.
"""
)

# {JSON_FORMAT_INSTRUCTION}
# Your response must follow this exact format:
# {TEST_SCRIPT_JSON_FORMAT}
# The keys must be exactly "test_script" and "test_script_explanation" - do not use different keys.


FIX_LLM_TASK = inspect.cleandoc(
    """
## Task:
- Generate a Bash (/bin/bash) script that:
- Follows the guidance provided in the README file to determine the appropriate build and test commands.
- The script should:
  - Assume that all source code and dependencies have already been downloaded and prepared.
  - Start by navigating to the /out/src directory using "cd /out/src".
  - If a build process is required and not already completed, perform the build steps first before executing the test steps.
  - Execute only the necessary build and test steps as described in the README, focusing specifically on testing procedures.
  - Avoid unnecessary detection of build tools or test commands. Instead, implement exactly what the README specifies for building and running tests.
  - Provide clear logging of each step, including success and failure messages.
  - Fail early if any command fails (set -e).
  - Do not include "exit" commands in the script, as the external system will handle process termination.
"""
)
