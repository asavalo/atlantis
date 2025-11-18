import inspect

# FILE EXTRACTOR

FILE_EXTRACTOR_SYSTEM_PROMPT = """You are a helpful assistant that analyzes project information to find relevant files.
Your task is to identify files that are explicitly mentioned in the provided project information.

Important rules:
1. Only list files that are explicitly mentioned in the text
2. Do not make assumptions or create file names that aren't mentioned
3. Look for file references in:
   - File paths shown in "=== File: ... ===" headers
   - Links to files (e.g., [file](path/to/file))
   - Direct file name mentions in the text
4. If a file is mentioned multiple times, list it only once
5. Return only the file names (without paths), one per line, without any additional text or explanations

Example output format:
README.md
contributing.md
setup.py
"""

FILE_EXTRACTOR_KEYWORDS = {
    "test": [
        "VALGRIND.md",
        "CONTRIBUTING.md",
        "INSTALL.md",
        "BUILD.md",
        "BUILDING.md",
        "HACKING.md",
        "run_tests.sh",
        "run_test.sh",
        "build.sh",
        "build_test.sh",
        "test_build.sh",
        "test.sh",
        "fuzz_test.sh",
        "fuzzing.md",
        "FUZZING.md",
        "Dockerfile",
        "Dockerfile.test",
        "CMakeLists.txt",
        "Makefile",
        "Makefile.test",
        "configure",
        "configure.ac",
        "autogen.sh",
        "setup.py",
        "requirements.txt",
        "test-requirements.txt",
    ],
    "missing_file": [
        ".h",
        ".c",
        ".cpp",
        ".py",
        ".sh",
        ".js",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".txt",
        ".md",
        ".so",
        ".dll",
        ".exe",
        ".bin",
        "Makefile",
        "CMakeLists.txt",
        "configure",
        "autogen.sh",
        "setup.py",
        "requirements.txt",
    ],
}

FILE_EXTRACTOR_PROMPTS = {
    "test": inspect.cleandoc(
        """
        Based on the following project information, please identify and list all files that contain test-related information.
        Focus on files that contain:
        - Test framework and requirements
        - Test dependencies and their versions
        - Test execution steps and commands
        - Test environment setup requirements
        - Test/CI configuration
        - Test script generation guidelines
        - Test dependencies
        - Test environment setup
        - Test execution flow
        - Test output requirements
        
        Project Information:
        {content}
        
        Please respond with a list of file paths only, one per line, in the format:
        contribution.md
        run_test.log
        test/README.md
        etc...
        
        Only include the file paths, no additional text or explanations.
    """
    ),
    "missing_file": inspect.cleandoc(
        """
        Based on the following error output, please identify and list all missing files or commands that are mentioned.
        Focus on:
        - Files that are reported as "not found"
        - Commands that are reported as "command not found"
        - Files mentioned in error messages like "No such file or directory"
        - Files mentioned in "can't open file" errors
        - Files mentioned in "Permission denied" errors
        - Files mentioned in "Errno 2" errors
        
        Error Output:
        {content}
        
        Please respond with a list of file or command names only, one per line, without paths or additional text.
        For example:
        gcc
        make
        config.h
        libssl.so
        etc...
        
        Only include the file or command names, no additional text or explanations.
    """
    ),
}
