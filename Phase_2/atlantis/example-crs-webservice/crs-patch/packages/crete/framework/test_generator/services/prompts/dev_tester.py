import inspect

from .json_format import JSON_FORMAT_INSTRUCTION

# DEV TESTER

DEV_TESTER_JSON_FORMAT = """
{
    "call_stack_maker_script": "#!/bin/bash\\n...",
    "dev_tester_script": "#!/bin/bash\\n...",
    "explanation": "Brief explanation of how the scripts work"
}
"""

DEV_TESTER_SYSTEM_PROMPT = inspect.cleandoc(
    f"""
    You are an AI assistant specialized in creating test utilities for fuzzing projects.
    Your task is to generate two shell scripts based on an existing test script:
    
    1. call_stack_maker.sh - A script that uses strace and ltrace to analyze function calls in tests
    2. dev_tester.sh - A script that runs specific tests instead of the entire test suite
    
    {JSON_FORMAT_INSTRUCTION}
    Your response must follow this exact format:
    {DEV_TESTER_JSON_FORMAT}
    """
)

DEV_TESTER_USER_PROMPT_TEMPLATE = inspect.cleandoc(
    """
    I need to create two shell scripts for the project '{project_name}' based on the following test script:
    
    ```
    {test_script}
    ```
    
    {validate_info_section}
    
    Please generate:
    
    1. call_stack_maker.sh:
       - This script should automatically find and identify all test files from the original test script
       - It should parse the test file names and create a list of them
       - It should use strace and ltrace to analyze which functions are called during test execution
       - IMPORTANT: The script should ALWAYS look for test files in the /out/src directory (e.g., using commands like "find /out/src -name ~~")
       - For each test file, it should create:
         * /out/test/dev_tester/callstack/[test_file_name]/strace.log
         * /out/test/dev_tester/callstack/[test_file_name]/ltrace.log
         * /out/test/dev_tester/callstack/[test_file_name]/path.txt (containing the full path to the test file)
       - IMPORTANT: The script should NOT use hardcoded test file names like "test_file1.py", "test_file2.py"
       - Instead, it should extract the actual test file names from the original test script or by scanning the /out/src directory
       - [test_file_name] should be the actual test file name without wildcards or special characters
       - The script should include logic to parse and extract test file names from commands in the original test script
       - The number of test_file_name folders should match the number of successful tests
       - IMPORTANT: All output files must be saved to /out/test/dev_tester/callstack directory, NOT to /out/src/callstack
    
    2. dev_tester.sh:
       - This script should accept a list of test file paths as arguments
       - It should run only the specified tests, not the entire test suite
       - It should maintain the same environment and setup as the original test script
       - It should report success/failure for each test
       - It should use the path.txt file to locate the original test file
    
    Both scripts should be well-commented, robust, and handle errors gracefully.
    ALL COMMENTS IN THE CODE MUST BE IN ENGLISH, not in any other language.
    
    Your response MUST be a valid JSON object with exactly these keys:
    {json_format}
    
    Do not include any text outside of the JSON object. Do not include markdown formatting like ```json or ``` around your response.
    """
)
