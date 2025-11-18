import logging
from typing import cast

import pytest
from crete.framework.test_generator.contexts import TestGenerationContext
from crete.framework.test_generator.services.validator import LLMTestValidator
from python_llm.api.actors import LlmApiManager
from python_oss_fuzz.path.globals import OSS_FUZZ_DIRECTORY


@pytest.mark.vcr()
def test_validator() -> None:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    project_name = "adal"
    test_result_name = "test_result_log_0.txt"

    # Create a mock context for validation
    context = cast(
        TestGenerationContext,
        {
            "logger": logger,
            "language_parser": None,  # Required for TestGenerationContext
            "environment": None,  # Not needed for validation
            "pool": type(
                "obj",
                (object,),
                {"out_directory": OSS_FUZZ_DIRECTORY / "build" / "out" / project_name},
            ),  # Mock pool with out_directory
            "detection": None,  # Required for TestGenerationContext
        },
    )

    test_result_path = context["pool"].out_directory / "test" / test_result_name

    try:
        if not test_result_path.exists():
            logger.warning(
                f"Test result file not found: {test_result_path}. Skipping test."
            )
            return

        logger.info(f"Reading test result from: {test_result_path}")
        test_result = test_result_path.read_text(encoding="utf-8")

        # Extract stdout and stderr from test result
        stdout = ""
        stderr = ""
        current_section = ""

        for line in test_result.split("\n"):
            if line.startswith("[stdout]"):
                current_section = "stdout"
            elif line.startswith("[stderr]"):
                current_section = "stderr"
            elif line.startswith("[error]"):
                current_section = "error"
            elif line.startswith("[validation]"):
                current_section = "validation"
            elif line and not line.startswith("["):
                if current_section == "stdout":
                    stdout += line + "\n"
                elif current_section == "stderr":
                    stderr += line + "\n"

        logger.info("Initializing LLM API Manager")
        llm_api_manager = LlmApiManager.from_environment(model="gpt-4o")
        validator = LLMTestValidator(llm_api_manager)

        logger.info("Validating test result")
        # Combine stdout and stderr into a single output
        combined_output = f"[stdout]\n{stdout}\n\n"
        if stderr.strip():
            combined_output += f"[stderr]\n{stderr}\n"

        validation_result = validator.validate(context, combined_output)

        if validation_result:
            logger.info(f"Validation result: {validation_result}")
            assert validation_result["test_success"] is not None, (
                "Test success status is missing"
            )
        else:
            logger.warning("No validation result returned")

    except Exception as e:
        logger.error(f"Validation failed: {e}")
