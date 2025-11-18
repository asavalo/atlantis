import inspect

from .json_format import JSON_FORMAT_INSTRUCTION

# VALIDATOR

VALIDATOR_JSON_FORMAT = """
{
    "build_success": boolean,
    "test_success": boolean,
    "test_summary": {
        "total_tests": int,
        "successful_tests": int,
        "failures": int,
        "errors": int,
        "skipped": int
    },
    "validation_reason": string,  // Detailed explanation of the test results
    "error_fix_guideline": string  // Specific guidance on how to fix errors based on directory structure
}
"""

VALIDATOR_SYSTEM_PROMPT = inspect.cleandoc(
    f"""
You are an AI assistant responsible for validating build and test results.
Your task is to analyze the provided build and test logs, evaluate whether the build and test processes were fully successful, and identify any issues.
{JSON_FORMAT_INSTRUCTION}
Your response must follow this exact format:
{VALIDATOR_JSON_FORMAT}
"""
)

TEST_ANALYSIS_TASK = """
Please analyze the test results in detail and provide:
1. Total number of tests that were run
2. Number of successful tests
3. Number of failed tests
4. Number of errors encountered
5. Number of skipped tests

Explain the test results and any notable patterns or issues found.
"""

TEST_ANALYSIS_FORMAT = f"""
Your response MUST be a valid JSON object with exactly these keys:
{VALIDATOR_JSON_FORMAT}
Do not include any text outside of the JSON object. Do not include markdown formatting like ```json or ``` around your response.
"""
