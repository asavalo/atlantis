from pathlib import Path
from typing import Dict, List, Optional, TypedDict, cast

from crete.atoms.detection import Detection
from crete.framework.test_generator.contexts import TestGenerationContext
from python_llm.api.actors import LlmApiManager

from .. import functions
from .constants import (
    CONTAINER_SRC_DIR,
    EXTRA_INFO_FILE_NAME,
    EXTRA_INFO_KEY,
    EXTRINFO_KEY,
    FILE_MAX_TOKEN,
    INFORMATION_DIR,
    LLM_MAX_TOKEN,
    LLM_TEST_INFO_KEY,
    LLMTESTINFO_KEY,
    TEST_DIR,
    TEST_INFO_FILE_NAME,
)
from .prompts import TEST_INFO_PROMPT, TEST_INFO_SYSTEM_PROMPT

TEST_INFORMATION_DIR = Path(TEST_DIR) / INFORMATION_DIR

IMPORTANT_FILES = ["README", "build", "Makefile", "hacking"]


class TestInformationDict(TypedDict, total=False):
    BUILD: str
    FUZZER: str
    MAKEFILE: str
    CMAKE: str
    EXTRA_INFO: str
    LLM_TEST_INFO: str
    DirectoryStructure: str
    __extra__: Dict[str, str]


ProjectInfoDict = Dict[str, Optional[str]]


class LLMInformationGenerator:
    def __init__(self, llm_api_manager: LlmApiManager) -> None:
        self.llm_api_manager = llm_api_manager

    def generate(
        self, context: TestGenerationContext, detection: Detection
    ) -> TestInformationDict:
        out_directory = context["pool"].out_directory
        information_dir = out_directory / TEST_INFORMATION_DIR
        information_dir.mkdir(parents=True, exist_ok=True)
        test_info_file_path = information_dir / TEST_INFO_FILE_NAME

        if test_info_file_path.exists():
            context["logger"].info(
                f"LLM test info file already exists at {test_info_file_path}. Skipping extraction."
            )
            all_info: TestInformationDict = {}

            for file_path in information_dir.glob("*.txt"):
                content = file_path.read_text(encoding="utf-8")
                key = file_path.stem.upper()
                if key == LLMTESTINFO_KEY:
                    key = LLM_TEST_INFO_KEY
                elif key == EXTRINFO_KEY:
                    key = EXTRA_INFO_KEY
                all_info[key] = content

            return all_info

        all_info: TestInformationDict = {}
        all_info.update(self.extract_directory_structure_info(context, detection))

        for file_type in IMPORTANT_FILES:
            file_name = file_type.upper() + ".all.txt"
            all_info.update(
                cast(
                    TestInformationDict,
                    functions.extract_file_info(
                        context,
                        detection,
                        file_type,
                        file_name,
                        file_type.upper(),
                        information_dir,
                    ),
                )
            )

        all_info.update(self.extract_extra_info(context, detection))
        all_info.update(self.summary_llm_test_info(context, detection))

        return all_info

    def extract_extra_info(
        self, context: TestGenerationContext, detection: Detection
    ) -> TestInformationDict:
        out_directory = context["pool"].out_directory
        information_dir = out_directory / TEST_INFORMATION_DIR
        information_dir.mkdir(parents=True, exist_ok=True)
        extra_info_file_path = information_dir / EXTRA_INFO_FILE_NAME

        if extra_info_file_path.exists():
            context["logger"].info(
                f"Extra info file already exists at {extra_info_file_path}. Skipping extraction."
            )
            extra_content = extra_info_file_path.read_text(encoding="utf-8")
            return cast(TestInformationDict, {EXTRA_INFO_KEY: extra_content})

        # Read all information files
        project_info = ""
        for file_path in information_dir.glob("*.txt"):
            if file_path.name != "DirectoryStructure.txt":
                content = file_path.read_text(encoding="utf-8")
                project_info += f"\n=== File: {file_path.name} ===\n{content}\n"

        # Get relevant files using both human and LLM methods
        human_file_names = functions.extract_file_by_human(
            context, detection, project_info, "test"
        )
        llm_file_names = functions.extract_file_by_llm(
            context, detection, self.llm_api_manager, project_info, "test"
        )

        # Combine and limit to 10 file names
        extra_file_names = list(set(human_file_names + llm_file_names))[:10]
        extra_files: List[str] = []

        # For each file name, find the actual file in the system
        for file_name in extra_file_names:
            files = functions.find_files(
                context,
                detection,
                file_name,
                max_depth=5,
                use_iname=False,
                add_wildcards=False,
            )

            # Sort by path depth and limit to the first one
            if files:
                files.sort(key=lambda path: path.count("/"))
                files = files[:1]
                extra_files.extend(files)

        relevant_files = extra_files[:10]

        # Read and combine content from relevant files
        content = ""
        for file_path in relevant_files:
            file_content = functions.read_file_content(context, detection, file_path)
            if file_content:
                file_content = functions.truncate_with_token_constraint(
                    file_content, int(FILE_MAX_TOKEN / 4)
                )
                content += f"\n=== File: {file_path} ===\n{file_content}\n"

        extra_info_file_path.write_text(content, encoding="utf-8")
        return cast(TestInformationDict, {EXTRA_INFO_KEY: content})

    def summary_llm_test_info(
        self, context: TestGenerationContext, detection: Detection
    ) -> TestInformationDict:
        out_directory = context["pool"].out_directory
        information_dir = out_directory / TEST_INFORMATION_DIR
        information_dir.mkdir(parents=True, exist_ok=True)
        test_info_file_path = information_dir / TEST_INFO_FILE_NAME

        if test_info_file_path.exists():
            context["logger"].info(
                f"LLM test info file already exists at {test_info_file_path}. Skipping extraction."
            )
            test_info_content = test_info_file_path.read_text(encoding="utf-8")
            return cast(TestInformationDict, {LLM_TEST_INFO_KEY: test_info_content})

        # Read all information files EXCEPT DirectoryStructure.txt
        project_info = ""
        for file_path in information_dir.glob("*.txt"):
            if file_path.name != "DirectoryStructure.txt":
                content = file_path.read_text(encoding="utf-8")
                project_info += f"\n=== File: {file_path.name} ===\n{content}\n"

        # Generate test information prompt
        test_info_prompt = TEST_INFO_PROMPT.format(
            project_info=functions.truncate_with_token_constraint(
                project_info, LLM_MAX_TOKEN
            )
        )

        # Get LLM response
        try:
            chat_model = self.llm_api_manager.langchain_litellm()
            response = chat_model.invoke(
                [
                    {"role": "system", "content": TEST_INFO_SYSTEM_PROMPT},
                    {"role": "user", "content": test_info_prompt},
                ]
            )
            llm_response = cast(str, response.content)  # pyright: ignore
        except Exception as e:
            llm_response = f"Error getting LLM response: {str(e)}"

        # Save only response
        test_info_file_path.write_text(llm_response, encoding="utf-8")

        return cast(TestInformationDict, {LLM_TEST_INFO_KEY: llm_response})

    def extract_directory_structure_info(
        self, context: TestGenerationContext, detection: Detection
    ) -> TestInformationDict:
        out_directory = context["pool"].out_directory
        information_dir = out_directory / TEST_INFORMATION_DIR
        information_dir.mkdir(parents=True, exist_ok=True)
        structure_file_path = information_dir / "DirectoryStructure.txt"

        if structure_file_path.exists():
            context["logger"].info(
                f"Directory structure file already exists at {structure_file_path}. Skipping extraction."
            )
            structure_content = structure_file_path.read_text(encoding="utf-8")
            return cast(TestInformationDict, {"DirectoryStructure": structure_content})

        # Define keywords to include (test-related files, etc.)
        include_keywords: List[str] = [
            "test",
            "readme",
            ".md",
            "example",
            "sample",
            "doc",
            "tutorial",
        ]

        # Define keywords to exclude
        exclude_keywords: List[str] = [
            ".git",
            ".svn",
            ".vscode",
            "__pycache__",
            "node_modules",
            "build/",
        ]

        # Directories to exclude
        excluded_directories = [
            ".aixcc",
            "fuzztest",
            "honggfuzz",
            "aflplusplus",
            "libfuzzer",
            ".git",
            "__pycache__",
            "node_modules",
        ]

        # Maximum number of files to display per directory
        MAX_FILES_PER_DIR = 10

        content = ""

        # Extract basic directory structure
        for base_dir in ["/out", "/src"]:
            content += f"# {base_dir} Directory Structure\n"

            # Get directory list
            stdout, _ = context["environment"].shell(
                context,
                f"export TERM=dumb PY_COLORS=0 NO_COLOR=1 CLICOLOR=0 CLICOLOR_FORCE=0 && find {base_dir} -maxdepth 2 -type d",
            )
            directories = [
                line.strip()
                for line in stdout.strip().split("\n")
                if line.startswith(base_dir)
                and not any(excluded in line for excluded in excluded_directories)
            ]

            # Get file list for each directory
            for directory in directories:
                content += f"\n## Directory: {directory}\n"

                # Regular file list
                stdout, _ = context["environment"].shell(
                    context,
                    f"export TERM=dumb PY_COLORS=0 NO_COLOR=1 CLICOLOR=0 CLICOLOR_FORCE=0 && find {directory} -maxdepth 1 -type f",
                )
                all_files = [
                    line.strip()
                    for line in stdout.strip().split("\n")
                    if line.startswith(directory)
                    and not any(
                        excluded in line.lower() for excluded in exclude_keywords
                    )
                ]

                # If total files are 10 or fewer, display all of them
                if len(all_files) <= MAX_FILES_PER_DIR:
                    if all_files:
                        content += "### Files:\n"
                        content += "\n".join(all_files) + "\n\n"
                    else:
                        content += "### No files found in this directory\n\n"
                else:
                    # More than 10 files, prioritize by keywords
                    # Important files (containing keywords) displayed first
                    important_files = [
                        f
                        for f in all_files
                        if any(keyword in f.lower() for keyword in include_keywords)
                    ]

                    other_files = [f for f in all_files if f not in important_files]

                    # Calculate how many files to display from each category
                    if len(important_files) >= MAX_FILES_PER_DIR:
                        # If important files are already 10 or more, just show those
                        files_to_display = important_files[:MAX_FILES_PER_DIR]
                        content += (
                            "### Important Files (showing 10 of "
                            + str(len(all_files))
                            + "):\n"
                        )
                        content += "\n".join(files_to_display) + "\n"
                        content += "...(more files exist)\n\n"
                    else:
                        # Show all important files and fill the rest with other files
                        remaining_slots = MAX_FILES_PER_DIR - len(important_files)
                        other_files_to_display = other_files[:remaining_slots]

                        content += (
                            "### Files (showing 10 of " + str(len(all_files)) + "):\n"
                        )

                        if important_files:
                            content += "# Important Files:\n"
                            content += "\n".join(important_files) + "\n\n"

                        if other_files_to_display:
                            content += "# Other Files:\n"
                            content += "\n".join(other_files_to_display) + "\n"

                        content += "...(more files exist)\n\n"

            # Special search for test-related files
            content += f"\n## Test-Related Files in {base_dir}\n"
            for keyword in ["test", "example", "sample"]:
                find_command = f"find {base_dir} -type f -name '*{keyword}*' | grep -v '{'|'.join(excluded_directories)}' | head -n 10"
                stdout, _ = context["environment"].shell(
                    context,
                    f"export TERM=dumb PY_COLORS=0 NO_COLOR=1 CLICOLOR=0 CLICOLOR_FORCE=0 && {find_command}",
                )
                if stdout.strip():
                    content += f"\n### Files matching '*{keyword}*' pattern:\n"
                    files = stdout.strip().split("\n")
                    content += "\n".join(files)
                    if (
                        len(files) == 10
                    ):  # If we got exactly 10 files, there might be more
                        content += "\n...(possibly more files exist)\n"
                    content += "\n"

            content += "\n" + "-" * 50 + "\n\n"

        structure_file_path.write_text(content, encoding="utf-8")
        return cast(TestInformationDict, {"DirectoryStructure": content})


def extract_information_for_test_generation(
    context: TestGenerationContext, detection: Detection
) -> TestInformationDict:
    """
    Extract all necessary information for test generation.
    """
    out_directory = context["pool"].out_directory
    information_dir = out_directory / TEST_DIR / INFORMATION_DIR
    information_dir.mkdir(parents=True, exist_ok=True)

    info_dict: TestInformationDict = {}

    # Extract build information
    build_info = functions.extract_file_info(
        context, detection, "build", "build.txt", "BUILD", information_dir
    )
    info_dict.update(cast(TestInformationDict, build_info))

    # Extract fuzzer information
    fuzzer_info = functions.extract_file_info(
        context, detection, "fuzz", "fuzzer.txt", "FUZZER", information_dir
    )
    info_dict.update(cast(TestInformationDict, fuzzer_info))

    # Extract Makefile information
    makefile_info = functions.extract_file_info(
        context, detection, "Makefile", "makefile.txt", "MAKEFILE", information_dir
    )
    info_dict.update(cast(TestInformationDict, makefile_info))

    # Extract CMake information
    cmake_info = functions.extract_file_info(
        context, detection, "CMakeLists.txt", "cmake.txt", "CMAKE", information_dir
    )
    info_dict.update(cast(TestInformationDict, cmake_info))

    # Extract extra information
    extra_info_path = information_dir / EXTRA_INFO_FILE_NAME
    if not extra_info_path.exists():
        # Get list of all source files
        stdout, _ = context["environment"].shell(
            context,
            f"export TERM=dumb PY_COLORS=0 NO_COLOR=1 CLICOLOR=0 CLICOLOR_FORCE=0 && find {CONTAINER_SRC_DIR} -type f -name '*.c' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp' | head -n 10",
        )
        extra_info_path.write_text(stdout, encoding="utf-8")

    extra_info = functions.extract_file_info(
        context, detection, "", EXTRA_INFO_FILE_NAME, EXTRA_INFO_KEY, information_dir
    )
    info_dict.update(cast(TestInformationDict, extra_info))

    # Extract LLM test information
    llm_test_info_path = information_dir / TEST_INFO_FILE_NAME
    if not llm_test_info_path.exists():
        llm_test_info_content = (
            "This is a test generation task for an OSS-Fuzz project."
        )
        llm_test_info_path.write_text(llm_test_info_content, encoding="utf-8")

    llm_test_info = functions.extract_file_info(
        context, detection, "", TEST_INFO_FILE_NAME, LLM_TEST_INFO_KEY, information_dir
    )
    info_dict.update(cast(TestInformationDict, llm_test_info))

    return info_dict
