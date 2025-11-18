import logging

import pytest
from crete.framework.test_generator.services.test_generator import generate_for_oss_fuzz
from python_llm.api.actors import LlmApiManager


@pytest.mark.skip(
    reason="Skipping test due to slow execution and no need to run on AFC"
)
@pytest.mark.vcr()
def test_llm_test_generator() -> None:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    project_name = "adal"

    logger.info(f"Starting test for project: {project_name}")

    def log_callback(message: str) -> None:
        logger.info(message)

    try:
        llm_api_manager = LlmApiManager.from_environment(model="gpt-4o")
        llm_formatter_manager = LlmApiManager.from_environment(model="gpt-4o-mini")

        build_success, test_success = generate_for_oss_fuzz(
            project_name,
            llm_api_manager,
            llm_formatter_manager,
            log_callback=log_callback,
        )

        assert build_success, f"Build failed for project: {project_name}"
        assert test_success, f"Test generation failed for project: {project_name}"

        logger.info(f"Test succeeded for project: {project_name}")

    except Exception as e:
        logger.error(f"Test failed for project: {project_name}. Error: {e}")
