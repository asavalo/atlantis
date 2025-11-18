import inspect
import json
import logging
import re
from typing import Any, Callable, Optional, Tuple, cast

from crete.atoms.detection import Detection
from crete.framework.test_generator.contexts import TestGenerationContext
from crete.framework.test_generator.functions import (
    build_oss_project,
    clean_project_completely,
    clean_test_generator,
    get_success_script_path,
    make_and_check_test_script,
    make_oss_context,
    make_usermode,
    reset_usermode,
)
from crete.framework.test_generator.models import TestGenerationResult
from crete.framework.test_generator.protocols import TestGeneratorProtocol
from crete.framework.test_generator.services.information import (
    LLMInformationGenerator,
    TestInformationDict,
)
from crete.framework.test_generator.services.validator import LLMTestValidator
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, ValidationError
from python_llm.api.actors import LlmApiManager

from .constants import (
    EXTRA_INFO_KEY,
    EXTRINFO_KEY,
    INFORMATION_DIR,
    LLM_TEST_INFO_KEY,
    LLMTESTINFO_KEY,
    SUCCESS_DIR,
    TEST_DIR,
    TEST_SCRIPT_EXT,
    TEST_SCRIPT_PREFIX,
)
from .prompts import (  # GENERATOR_JSON_OUTPUT_FORMAT,
    ERROR_FIX_MANUAL,
    FIX_LLM_TASK,
    GENERATOR_SYSTEM_PROMPT,
    TEST_RESULT_SUMMARY,
    USER_FORMAT_TEST_SCRIPT,
)


class _LLMOutputForTestFix(BaseModel):
    test_script: str
    test_script_explanation: str


class LLMTestGenerator(TestGeneratorProtocol):
    def __init__(
        self,
        llm_api_manager: LlmApiManager,
        llm_formatter_manager: LlmApiManager,
        max_retries: int = 5,
    ) -> None:
        self.llm_api_manager = llm_api_manager
        self.llm_formatter_manager = llm_formatter_manager
        self.max_retries = max_retries
        self.validator = LLMTestValidator(self.llm_api_manager)

    def generate(
        self, context: TestGenerationContext, detection: Detection
    ) -> TestGenerationResult | None:
        prev_result = None
        for attempt in range(self.max_retries):
            context["logger"].info(
                f"Running test attempt {attempt + 1}/{self.max_retries}..."
            )
            result = self._try_generate(context, detection, prev_result)
            if result and result.status == "success":
                return result
            prev_result = result
        return None

    def cached_success_or_recent_test(
        self, context: TestGenerationContext, detection: Detection
    ) -> tuple[Optional[TestGenerationResult], Optional[TestGenerationResult]]:
        """
        Check if there is a cached successful test script and reuse it if available.
        If no successful test exists, find the latest generated test and its result log.

        Returns:
            tuple: (result, prev_result)
                - result: TestGenerationResult if successful, None if failed
                - prev_result: TestGenerationResult with failure info if failed, None if successful or no cache
        """
        out_directory = context["pool"].out_directory
        success_dir = out_directory / TEST_DIR / SUCCESS_DIR
        success_script_path = get_success_script_path(context, detection)

        # Check if success directory and successful test script exist
        if success_dir.exists() and success_script_path.exists():
            context["logger"].info(
                f"Found existing successful test script at {success_script_path}"
            )

            test_script = success_script_path.read_text(encoding="utf-8")

            result = make_and_check_test_script(
                context, detection, test_script, self.validator
            )

            if result and result.status == "success":
                context["logger"].info(
                    "Previously successful test passed validation again"
                )
                return result, None

            if result:
                context["logger"].warning(
                    "Previously successful test failed validation, removing from success directory"
                )
                try:
                    success_script_path.unlink()
                    context["logger"].info(
                        f"Removed {success_script_path} due to validation failure"
                    )
                except Exception as e:
                    context["logger"].error(
                        f"Failed to remove {success_script_path}: {e}"
                    )

                return None, result

        # If no successful test exists, find the latest generated test
        test_dir = out_directory / TEST_DIR
        if test_dir.exists():
            # Find generated test scripts
            existing_tests = sorted(
                test_dir.glob(f"{TEST_SCRIPT_PREFIX}_*{TEST_SCRIPT_EXT}")
            )
            if existing_tests:
                latest_test_script = existing_tests[-1]
                context["logger"].info(
                    f"No successful test found, using latest test script: {latest_test_script.name}"
                )

                # Find the result log for this test
                result_log_path = latest_test_script.with_name(
                    latest_test_script.name.replace(".sh", ".txt").replace(
                        "generated_test_", "test_result_log_"
                    )
                )

                if result_log_path.exists():
                    context["logger"].info(
                        f"Found result log for latest test: {result_log_path}"
                    )

                    # Read test script and result log to create TestGenerationResult
                    test_script = latest_test_script.read_text(encoding="utf-8")
                    log_content = result_log_path.read_text(encoding="utf-8")

                    # Create TestGenerationResult with previous failure information
                    prev_result = TestGenerationResult(
                        status="failure", output=log_content, path=latest_test_script
                    )

                    # script_code is a property accessed through path
                    # No additional work needed as we already set latest_test_script as path

                    return None, prev_result

        return None, None

    def _try_generate(
        self,
        context: TestGenerationContext,
        detection: Detection,
        prev_result: Optional[TestGenerationResult] = None,
    ) -> Optional[TestGenerationResult]:
        info_dict: TestInformationDict = {}

        # Read all information files
        out_directory = context["pool"].out_directory
        information_dir = out_directory / TEST_DIR / INFORMATION_DIR
        for file_path in information_dir.glob("*.txt"):
            content = file_path.read_text(encoding="utf-8")
            key = file_path.stem.upper()
            if key == LLMTESTINFO_KEY:
                key = LLM_TEST_INFO_KEY
            elif key == EXTRINFO_KEY:
                key = EXTRA_INFO_KEY
            info_dict[key] = content

        # Check for cached successful test or recent test
        cached_result, cached_failure = self.cached_success_or_recent_test(
            context, detection
        )
        if cached_result:
            return cached_result

        # If cached test failed, use its failure info as prev_result
        if cached_failure:
            prev_result = cached_failure

        # Request new test generation from LLM
        output = self._query_llm_for_test_generation(context, info_dict, prev_result)
        if not output:
            return None

        return make_and_check_test_script(
            context, detection, output.test_script, self.validator
        )

    def _query_llm_for_test_generation(
        self,
        context: TestGenerationContext,
        input_data: TestInformationDict,
        prev_result: TestGenerationResult | None = None,
    ) -> _LLMOutputForTestFix | None:
        content_block = f"```json\n{json.dumps(input_data, indent=2)}\n```"
        error_info = ""

        if prev_result:
            error_info = (
                "\n## Previous Test Failure Logs:\n```\n" + prev_result.output + "\n```"
                "\n## Previous Test Script:\n```\n"
                + prev_result.script_code
                + "\n```"
                + ERROR_FIX_MANUAL
            )

        prompt = inspect.cleandoc(
            f"""
            I have extracted the following project information from an OSS-Fuzz project:
            {content_block}
            
            {FIX_LLM_TASK}

            {error_info}

            {TEST_RESULT_SUMMARY}
            """
        )

        chat_model = self.llm_api_manager.langchain_litellm()
        gen_script_response = chat_model.invoke(
            [
                {"role": "system", "content": GENERATOR_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ]
        )

        chat_model = self.llm_api_manager.langchain_litellm()
        formatted_response = chat_model.invoke(
            [
                {"role": "system", "content": GENERATOR_SYSTEM_PROMPT},
                {
                    "role": "assistant",
                    "content": gen_script_response.content,  # type: ignore
                },
                {"role": "user", "content": USER_FORMAT_TEST_SCRIPT},
            ]
        )

        response_text = cast(str, formatted_response.content).strip()  # pyright: ignore
        response_text = re.sub(r"```json\n|\n```", "", response_text)

        try:
            parsed_response = JsonOutputParser().parse(response_text)
        except json.JSONDecodeError:
            context["logger"].exception(
                f"Failed to parse JSON from LLM response: {response_text}"
            )
            return None

        try:
            llm_output = _LLMOutputForTestFix(**parsed_response)
        except ValidationError:
            context["logger"].exception(
                f"Failed to validate JSON from LLM response: {response_text}"
            )
            return None

        return llm_output


def generate_for_oss_fuzz(
    project_name: str,
    llm_api_manager: LlmApiManager,
    llm_formatter_manager: LlmApiManager,
    log_callback: Optional[Callable[[str], Any]] = None,
) -> Tuple[bool, bool]:
    """Generate tests for an OSS-Fuzz project.

    Args:
        project_name: Name of the OSS-Fuzz project
        llm_api_manager: LLM API manager for main tasks
        llm_formatter_manager: LLM API manager for formatting
        log_callback: Optional callback function for logging messages

    Returns:
        tuple: (build_success, test_success)
    """

    # Define logging function
    def log_message(message: str) -> None:
        if log_callback is not None:
            log_callback(message)
        else:
            logging.info(message)

    log_message(f"Starting build for project: {project_name}")

    build_success = False
    test_success = False
    environment_context = None
    detection = None

    try:
        # Create context and detection objects
        environment_context, detection = make_oss_context(project_name)

        # Set user permissions at the very beginning
        make_usermode(environment_context)
        log_message(f"Set user permissions for project: {project_name}")

        # Try to clean test generator files first (usually has fewer permission issues)
        clean_test_generator(environment_context, detection)

        try:
            # Attempt to clean project completely, but don't fail if it doesn't work
            clean_project_completely(environment_context, detection)
        except PermissionError as e:
            log_message(
                f"Permission error while cleaning project: {e}. Continuing anyway."
            )
        except Exception as e:
            log_message(f"Error while cleaning project: {e}. Continuing anyway.")

        # Build the project
        build_result = build_oss_project(environment_context, detection)
        if not build_result:
            raise ValueError(f"Build failed for {project_name}")

        build_success = True
        log_message(f"Build succeeded for project: {project_name}")

        # Generate project information
        info_generator = LLMInformationGenerator(llm_api_manager=llm_api_manager)
        info_generator.generate(environment_context, detection)
        log_message(f"Generated information for project: {project_name}")

        # Generate tests
        llm_test_builder = LLMTestGenerator(
            llm_api_manager=llm_api_manager, llm_formatter_manager=llm_formatter_manager
        )

        result = llm_test_builder.generate(environment_context, detection)

        if result is not None:
            test_success = True
            log_message(f"Test succeeded for project: {project_name}")
        else:
            log_message(f"Test failed for project: {project_name}")

    except Exception as e:
        log_message(f"Error processing project {project_name}: {e}")
    finally:
        # Reset permissions to default
        try:
            if build_success and environment_context is not None:
                reset_usermode(environment_context)
        except Exception as e:
            log_message(f"Error resetting permissions: {e}")

        log_message(f"Cleaned up project: {project_name}")

    return build_success, test_success
