JSON_FORMAT_INSTRUCTION = """
IMPORTANT: You MUST respond with a valid JSON object that strictly follows the format specified.
Do not include any text outside of the JSON object. Do not include markdown formatting like ```json or ``` around your response.
Use exactly the keys specified in the format, do not add or remove any keys.
"""

TEST_SCRIPT_JSON_FORMAT = """
{
    "test_script": "<generated shell script>",
    "test_script_explanation": "<detailed explanation of the test script or error resolution approach>"
}
"""

USER_FORMAT_TEST_SCRIPT = f"""
Extract generated test script from your previous response and provide it in json format without any tags and additional information.
The test script included in the json must be exactly the same as what you wrote previously.

{JSON_FORMAT_INSTRUCTION}

{TEST_SCRIPT_JSON_FORMAT}
"""
