import json
import re
from pathlib import Path
from typing import List, Optional

from crete.atoms.detection import Detection
from crete.framework.test_generator.contexts import TestGenerationContext
from crete.framework.test_generator.functions import (
    clean_dev_tester,
    container_path_from_host_absolute_path,
    get_success_log_path,
    get_success_script_path,
)
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, ValidationError
from python_llm.api.actors import LlmApiManager

from .constants import (
    CALL_STACK_MAKER_FILENAME,
    CALLSTACK_DIR,
    DEV_TESTER_DIR,
    DEV_TESTER_FILENAME,
    DEV_TESTER_MIN_CALLSTACK_FILES,
    DEV_TESTER_RESULT_FILENAME,
    TEST_DIR,
)
from .prompts import (
    DEV_TESTER_JSON_FORMAT,
    DEV_TESTER_SYSTEM_PROMPT,
    DEV_TESTER_USER_PROMPT_TEMPLATE,
)


class DevTesterOutput(BaseModel):
    """Output model for the DevLLMTestGenerator LLM response."""

    call_stack_maker_script: str
    dev_tester_script: str
    explanation: str


class DevLLMTestGenerator:
    def __init__(self, llm_api_manager: LlmApiManager) -> None:
        self.llm_api_manager = llm_api_manager

    def generate_scripts(
        self, context: TestGenerationContext, detection: Detection
    ) -> tuple[Path | None, Path | None]:
        # Determine output directory and project name
        out_directory = context["pool"].out_directory
        project_name = detection.project_name

        success_script_path = get_success_script_path(context, detection)

        if not success_script_path.exists():
            print(
                f"Success file {success_script_path} does not exist for project {project_name}"
            )
            return None, None

        # Check if successful test script exists
        if not success_script_path.exists():
            print(
                f"Success test script {success_script_path} does not exist for project {project_name}"
            )
            return None, None

        # Read the successful test script
        test_script = success_script_path.read_text(encoding="utf-8")

        test_result_log_path = get_success_log_path(context, detection)
        test_result_log = ""
        if test_result_log_path.exists():
            try:
                test_result_log = test_result_log_path.read_text(encoding="utf-8")
                print(f"Read test result log from {test_result_log_path}")
            except Exception as e:
                print(f"Error reading test result log: {e}")

        # Create dev_tester directory
        dev_tester_dir = out_directory / TEST_DIR / DEV_TESTER_DIR
        dev_tester_dir.mkdir(parents=True, exist_ok=True)

        # Create callstack directory
        callstack_dir = dev_tester_dir / CALLSTACK_DIR
        callstack_dir.mkdir(parents=True, exist_ok=True)

        # Generate scripts using LLM
        scripts = self._generate_scripts(project_name, test_script, test_result_log)
        if not scripts:
            return None, None

        # Write scripts to files
        call_stack_maker_path = dev_tester_dir / CALL_STACK_MAKER_FILENAME
        dev_tester_path = dev_tester_dir / DEV_TESTER_FILENAME

        call_stack_maker_path.write_text(
            scripts.call_stack_maker_script, encoding="utf-8"
        )
        dev_tester_path.write_text(scripts.dev_tester_script, encoding="utf-8")

        # Make scripts executable
        call_stack_maker_path.chmod(0o755)
        dev_tester_path.chmod(0o755)

        print(f"Generated dev_tester scripts for project {project_name}:")
        print(f"  - {call_stack_maker_path}")
        print(f"  - {dev_tester_path}")
        print(f"Explanation: {scripts.explanation}")

        return call_stack_maker_path, dev_tester_path

    def execute_scripts(
        self, context: TestGenerationContext, detection: Detection
    ) -> bool:
        out_directory = context["pool"].out_directory
        project_name = detection.project_name

        dev_tester_dir = out_directory / TEST_DIR / DEV_TESTER_DIR
        call_stack_maker_path = dev_tester_dir / CALL_STACK_MAKER_FILENAME
        dev_tester_path = dev_tester_dir / DEV_TESTER_FILENAME
        callstack_dir = dev_tester_dir / CALLSTACK_DIR
        success_script_path = get_success_script_path(context, detection)

        # Check if scripts exist
        if not call_stack_maker_path.exists() or not dev_tester_path.exists():
            print(f"Scripts not found at {dev_tester_dir}")
            return False

        # Check if success script exists
        if not success_script_path.exists():
            print(f"Success script not found at {success_script_path}")
            return False

        container_dev_tester_dir = container_path_from_host_absolute_path(
            context, dev_tester_dir, detection
        )
        container_call_stack_maker_path = container_path_from_host_absolute_path(
            context, call_stack_maker_path, detection
        )
        container_dev_tester_path = container_path_from_host_absolute_path(
            context, dev_tester_path, detection
        )
        container_success_script_path = container_path_from_host_absolute_path(
            context, success_script_path, detection
        )

        # Execute call_stack_maker.sh in container with environment setup
        print(
            f"Executing {call_stack_maker_path} for project {project_name} in container..."
        )
        try:
            # First run success script to ensure environment is set up, then install strace and ltrace, then execute call_stack_maker.sh
            cmd = f"chmod +x {container_success_script_path} && {container_success_script_path} && apt-get update && apt-get install -y strace ltrace && cd {container_dev_tester_dir} && chmod +x {container_call_stack_maker_path} && {container_call_stack_maker_path}"
            stdout, stderr = context["environment"].shell(context, cmd)

            # Save execution results
            call_stack_result = "[call_stack_maker.sh Execution Results]\n"
            call_stack_result += f"STDOUT:\n{stdout}\n\n"
            call_stack_result += f"STDERR:\n{stderr}\n\n"

            # Check if callstack directory exists and has subdirectories
            if not callstack_dir.exists():
                print(
                    f"Callstack directory {callstack_dir} does not exist after execution"
                )

                # Save failure results
                result_path = dev_tester_dir / DEV_TESTER_RESULT_FILENAME
                result_path.write_text(call_stack_result, encoding="utf-8")
                print(f"Call stack maker results saved to {result_path}")

                return False

            # Get test directories directly from host filesystem
            test_dirs = [d for d in callstack_dir.iterdir() if d.is_dir()]

            # Count trace files directly from host filesystem
            strace_count = sum(1 for _ in callstack_dir.glob("**/strace.log"))
            ltrace_count = sum(1 for _ in callstack_dir.glob("**/ltrace.log"))

            call_stack_result += f"Generated strace files: {strace_count}\n"
            call_stack_result += f"Generated ltrace files: {ltrace_count}\n\n"

            # Check if enough test directories were generated
            if len(test_dirs) >= DEV_TESTER_MIN_CALLSTACK_FILES:
                print(
                    f"Successfully generated trace files for {len(test_dirs)} test files"
                )

                # Extract test file names from directory names
                test_files: List[str] = [d.name for d in test_dirs]

                # Execute dev_tester.sh in container
                if test_files:
                    print(
                        f"Executing {dev_tester_path} with {len(test_files)} test files in container..."
                    )
                    try:
                        # Execute shell command in Docker container
                        test_files_str = " ".join(test_files)
                        dev_tester_cmd = f"cd {container_dev_tester_dir} && chmod +x {container_dev_tester_path} && {container_dev_tester_path} {test_files_str}"
                        dev_tester_stdout, dev_tester_stderr = context[
                            "environment"
                        ].shell(context, dev_tester_cmd)

                        # Save results
                        dev_tester_output = "[dev_tester.sh Execution Results]\n"
                        dev_tester_output += f"STDOUT:\n{dev_tester_stdout}\n\n"
                        dev_tester_output += f"STDERR:\n{dev_tester_stderr}\n\n"

                        # Save all results to file
                        result_path = dev_tester_dir / DEV_TESTER_RESULT_FILENAME
                        result_path.write_text(
                            call_stack_result + dev_tester_output, encoding="utf-8"
                        )
                        print(f"Dev tester results saved to {result_path}")

                        return True
                    except Exception as e:
                        print(f"Error executing {dev_tester_path} in container: {e}")
                        return False
                else:
                    print("No test files found in callstack directories")
                    return False
            else:
                print(
                    f"Not enough callstack files generated: {len(test_dirs)} < {DEV_TESTER_MIN_CALLSTACK_FILES}"
                )

                # Save failure results
                result_path = dev_tester_dir / DEV_TESTER_RESULT_FILENAME
                result_path.write_text(call_stack_result, encoding="utf-8")
                print(f"Call stack maker results saved to {result_path}")

                return False
        except Exception as e:
            print(f"Error executing {call_stack_maker_path} in container: {e}")
            return False

    def generate(self, context: TestGenerationContext, detection: Detection) -> bool:
        # Get project name from detection
        project_name = detection.project_name

        # Clean dev_tester directory before starting
        clean_dev_tester(context, detection)

        # Generate and execute scripts
        call_stack_maker_path, dev_tester_path = self.generate_scripts(
            context, detection
        )
        if call_stack_maker_path is None or dev_tester_path is None:
            context["logger"].warning(
                f"Failed to generate dev tester scripts for project {project_name}"
            )
            return False

        result = self.execute_scripts(context, detection)

        # Save results to context
        out_directory = context["pool"].out_directory
        dev_tester_dir = out_directory / TEST_DIR / DEV_TESTER_DIR
        result_path = dev_tester_dir / DEV_TESTER_RESULT_FILENAME

        if result:
            if result_path.exists():
                context["logger"].info(
                    f"Dev tester executed successfully for project {project_name}"
                )
                context["logger"].info(f"Results saved to {result_path}")
            else:
                context["logger"].warning(
                    f"Dev tester executed but no result file found at {result_path}"
                )
        else:
            context["logger"].warning(
                f"Failed to execute dev tester scripts for project {project_name}"
            )

        return result

    def _generate_scripts(
        self, project_name: str, test_script: str, test_result_log: str
    ) -> Optional[DevTesterOutput]:
        validate_info_section = ""
        if test_result_log:
            validate_info_section = f"""
            Additional information from test execution:
            ```
            {test_result_log}
            ```
            
            IMPORTANT: The number of test_file_name folders should match the number of successful tests.
            Each test_file_name should be the actual test file name without wildcards or special characters.
            
            Please consider this information when generating the scripts.
            """

        user_prompt = DEV_TESTER_USER_PROMPT_TEMPLATE.format(
            project_name=project_name,
            test_script=test_script,
            validate_info_section=validate_info_section,
            json_format=DEV_TESTER_JSON_FORMAT,
        )

        try:
            chat_model = self.llm_api_manager.langchain_litellm()
            response = chat_model.invoke(
                [
                    {"role": "system", "content": DEV_TESTER_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ]
            )

            # Handle response content safely
            response_content = getattr(response, "content", None)
            if not isinstance(response_content, str):
                print(
                    f"Error: LLM response content is not a string: {type(response_content)}"
                )
                return None

            response_text = response_content.strip()

            # Extract JSON from response if wrapped in markdown code blocks
            response_text = re.sub(r"```json\n|\n```", "", response_text)

            try:
                parsed_response = JsonOutputParser().parse(response_text)
            except json.JSONDecodeError as e:
                print(f"Failed to parse JSON from LLM response: {e}")
                print(f"Response: {response_text}")
                return None

            try:
                output = DevTesterOutput(**parsed_response)
                return output
            except ValidationError as e:
                print(f"Failed to validate LLM response: {e}")
                return None

        except Exception as e:
            print(f"Error generating scripts: {e}")
            return None
