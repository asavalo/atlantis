import inspect
import json
import re
from typing import TypedDict, cast

from crete.framework.test_generator.contexts import TestGenerationContext
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, ValidationError
from python_llm.api.actors import LlmApiManager

from .constants import INFORMATION_DIR, TEST_DIR
from .prompts import TEST_ANALYSIS_FORMAT, TEST_ANALYSIS_TASK, VALIDATOR_SYSTEM_PROMPT


class BuildInfoDict(TypedDict):
    stdout: str
    stderr: str


class AdditionalInfoDict(TypedDict):
    log_contents: dict[str, str]
    directory_structure: str


class ValidationResult(TypedDict):
    build_success: bool
    test_success: bool
    test_summary: dict[str, int]
    validation_reason: str
    error_fix_guideline: str


class _LLMValidationOutput(BaseModel):
    build_success: bool
    test_summary: dict[str, int] = {
        "total_tests": 0,
        "successful_tests": 0,
        "failed_tests": 0,
        "error_tests": 0,
        "skipped_tests": 0,
    }
    validation_reason: str
    error_fix_guideline: str = ""


class LLMTestValidator:
    def __init__(self, llm_api_manager: LlmApiManager) -> None:
        self.llm_api_manager = llm_api_manager

    def validate(
        self, context: TestGenerationContext, combined_output: str
    ) -> ValidationResult | None:
        build_info: BuildInfoDict = {"stdout": combined_output, "stderr": ""}

        # Get directory structure information
        directory_structure = self._get_directory_structure(context)

        additional_info: AdditionalInfoDict = {
            "log_contents": {},
            "directory_structure": directory_structure,
        }

        return self._query_llm_for_validation(context, build_info, additional_info)

    def _get_directory_structure(self, context: TestGenerationContext) -> str:
        """Get the directory structure information from DirectoryStructure.txt"""
        out_directory = context["pool"].out_directory
        structure_file_path = (
            out_directory / TEST_DIR / INFORMATION_DIR / "DirectoryStructure.txt"
        )

        if structure_file_path.exists():
            try:
                return structure_file_path.read_text(encoding="utf-8")
            except Exception as e:
                context["logger"].warning(
                    f"Failed to read directory structure file: {e}"
                )

        return "Directory structure information not available."

    def _query_llm_for_validation(
        self,
        context: TestGenerationContext,
        build_info: BuildInfoDict,
        additional_info: AdditionalInfoDict,
    ) -> ValidationResult | None:
        user_prompt = inspect.cleandoc(
            f"""
            Test Output:
            stdout:
            {build_info["stdout"]}

            stderr:
            {build_info["stderr"]}
            
            Directory Structure Information:
            {additional_info["directory_structure"]}

            {TEST_ANALYSIS_TASK}
            
            Additionally, if the test failed, please provide a detailed error_fix_guideline based on the directory structure information.
            This guideline should suggest specific files or directories that might be relevant to fixing the error,
            and provide concrete steps to resolve the issues.

            {TEST_ANALYSIS_FORMAT}
            """
        )

        chat_model = self.llm_api_manager.langchain_litellm()
        response = chat_model.invoke(
            [
                {"role": "system", "content": VALIDATOR_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ]
        )

        response_text = cast(str, response.content).strip()  # pyright: ignore
        response_text = re.sub(r"```json\n|\n```", "", response_text)

        try:
            parsed_response = JsonOutputParser().parse(response_text)
        except json.JSONDecodeError:
            context["logger"].exception(
                f"Failed to parse JSON from LLM response: {response_text}"
            )
            return None

        try:
            llm_output = _LLMValidationOutput(**parsed_response)

            test_success = llm_output.test_summary.get("successful_tests", 0) >= 1

            validation_result = ValidationResult(
                build_success=llm_output.build_success,
                test_success=test_success,
                test_summary=llm_output.test_summary,
                validation_reason=llm_output.validation_reason,
                error_fix_guideline=llm_output.error_fix_guideline,
            )

            return validation_result

        except ValidationError:
            context["logger"].exception(
                f"Failed to validate JSON from LLM response: {response_text}"
            )
            return None
