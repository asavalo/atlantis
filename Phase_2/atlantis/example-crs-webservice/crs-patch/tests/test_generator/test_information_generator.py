import logging

import pytest
from crete.framework.test_generator.functions import (
    build_oss_project,
    clean_project_completely,
    make_oss_context,
)
from crete.framework.test_generator.services.information import LLMInformationGenerator
from python_llm.api.actors import LlmApiManager


@pytest.mark.skip(
    reason="Skipping test due to slow execution and no need to run on AFC"
)
@pytest.mark.vcr()
def test_information_generator():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info("=== Testing Log Initialized ===")

    project_name = "adal"
    logger.info(f"Starting build for project: {project_name}")

    try:
        environment_context, detection = make_oss_context(project_name)

        logger.info(f"Build succeeded for project: {project_name}")
        clean_project_completely(environment_context, detection)

        result = build_oss_project(environment_context, detection)
        if result is False:
            raise ValueError(f"Build failed for {project_name}")

        llm_api_manager = LlmApiManager.from_environment(model="gpt-4o")
        info_generator = LLMInformationGenerator(llm_api_manager)

        # Generate all information at once
        logger.info("\n=== Generating Project Information ===")
        info_generator.generate(environment_context, detection)
        logger.info("=== Information Generation Complete ===")

    except Exception as e:
        logger.info(f"Test failed: {str(e)}")
    finally:
        # clean_project_completely(project_name)
        logger.info(f"Cleaned up project: {project_name}")
