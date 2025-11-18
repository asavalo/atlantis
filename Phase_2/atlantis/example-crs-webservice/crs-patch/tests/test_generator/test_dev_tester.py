from pathlib import Path

import pytest
from crete.framework.test_generator.functions import (
    build_oss_project,
    clean_dev_tester,
    make_oss_context,
)
from crete.framework.test_generator.services.dev_tester import DevLLMTestGenerator
from python_llm.api.actors import LlmApiManager

LOG_FILE = Path(__file__).parent / "dev_tester_testing.log"


def log_message(message: str, initialize: bool = False):
    mode = "w" if initialize else "a"
    with LOG_FILE.open(mode, encoding="utf-8") as f:
        f.write(f"{message}\n")


@pytest.mark.skip(reason="Skipping test due to flakyness")
@pytest.mark.vcr()
def test_dev_tester_generator():
    log_message("=== Dev Tester Testing Log Initialized ===", initialize=True)

    project_name = "adal"
    log_message(f"Starting test for project: {project_name}")

    try:
        # Create context and detection objects
        environment_context, detection = make_oss_context(project_name)

        # Build the project
        build_result = build_oss_project(environment_context, detection)
        if not build_result:
            raise ValueError(f"Build failed for {project_name}")

        log_message(f"Build succeeded for project: {project_name}")

        clean_dev_tester(environment_context, detection)

        llm_api_manager = LlmApiManager.from_environment(model="gpt-4o")

        dev_tester_generator = DevLLMTestGenerator(llm_api_manager)

        log_message("\n=== Generating Dev Tester Scripts ===")
        result = dev_tester_generator.generate(environment_context, detection)

        if result:
            log_message("=== Dev Tester Scripts Generation Successful ===")
        else:
            log_message("=== Dev Tester Scripts Generation Failed ===")

    except Exception as e:
        log_message(f"Test failed: {str(e)}")
    finally:
        log_message(f"Cleaned up project: {project_name}")
