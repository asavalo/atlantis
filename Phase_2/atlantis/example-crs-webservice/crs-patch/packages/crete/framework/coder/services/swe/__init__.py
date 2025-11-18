import atexit
import shutil
import tempfile
import subprocess
from pathlib import Path
from typing import Optional

import litellm
import sweagent
import yaml
from git import Repo
from pydantic.types import SecretStr
from python_llm.api.actors import LlmApiManager
from sweagent.agent.agents import DefaultAgent, DefaultAgentConfig
from sweagent.agent.models import GenericAPIModelConfig
from sweagent.agent.problem_statement import TextProblemStatement
from sweagent.environment.repo import LocalRepoConfig
from sweagent.environment.swe_env import EnvironmentConfig, SWEEnv
from sweagent.run.common import save_predictions
from swerex.deployment.config import DockerDeploymentConfig
from swerex.deployment.docker import DockerDeployment

from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.coder.contexts import CoderContext
from crete.framework.coder.protocols import CoderProtocol

litellm.suppress_debug_info = True
litellm.drop_params = True


class SweCoder(CoderProtocol):
    def __init__(
        self,
        agent_context: AgentContext,
        detection: Detection,
        llm_api_manager: LlmApiManager,
    ):
        super().__init__(agent_context, detection)
        self._llm_api_manager = llm_api_manager

        self._temperature = 0.3
        self._top_p = 0.95
        self._per_instance_cost_limit = 4.0

        self._swe_agent = self._create_swe_agent()
        self._swe_environment = _create_swe_agent_environment(
            Repo(
                self._agent_context["pool"].source_directory,
                search_parent_directories=True,
            )
        )
        self._session_directory = self._create_session_directory()

        atexit.register(self._safe_environment_close)

        self._swe_environment.start()

    def _get_container_id(self) -> Optional[str]:
        try:
            deployment = self._swe_environment.deployment
            if isinstance(deployment, DockerDeployment) and hasattr(
                deployment, "container_name"
            ):
                return deployment.container_name
        except AttributeError:
            self._agent_context["logger"].debug("Could not access deployment attribute")
        except TypeError:
            self._agent_context["logger"].debug(
                "Type error while accessing container name"
            )
        return None

    def _safe_environment_close(self) -> None:
        try:
            container_id = self._get_container_id()

            if container_id:
                self._agent_context["logger"].info(
                    f"Removing Docker container: {container_id}"
                )
                try:
                    result = subprocess.run(
                        ["docker", "rm", "-f", container_id], capture_output=True
                    )
                    if result.returncode == 0:
                        self._agent_context["logger"].info(
                            f"Docker container successfully removed: {container_id}"
                        )
                    else:
                        self._agent_context["logger"].warning(
                            f"Failed to remove Docker container: {container_id}, error: {result.stderr.decode('utf-8', errors='replace')}"
                        )
                except FileNotFoundError:
                    self._agent_context["logger"].error(
                        f"Docker command not found, could not remove container: {container_id}"
                    )
                except PermissionError:
                    self._agent_context["logger"].error(
                        f"Permission denied when trying to remove container: {container_id}"
                    )
                except subprocess.SubprocessError as e:
                    self._agent_context["logger"].error(
                        f"Subprocess error while removing container: {container_id}, error: {str(e)}"
                    )
                except Exception as e:
                    self._agent_context["logger"].error(
                        f"Unexpected error while removing container: {container_id}, error: {str(e)}"
                    )
        except Exception as e:
            self._agent_context["logger"].error(
                f"Error in _safe_environment_close: {str(e)}"
            )

    def __del__(self) -> None:
        self._safe_environment_close()

    def _create_swe_agent(self) -> DefaultAgent:
        config_file = sweagent.CONFIG_DIR / "default.yaml"
        config_text = yaml.safe_load(config_file.read_text())

        agent_config = DefaultAgentConfig(
            model=GenericAPIModelConfig(
                name=self._llm_api_manager.model,
                per_instance_cost_limit=self._per_instance_cost_limit,
                temperature=self._temperature,
                top_p=self._top_p,
                api_base=self._llm_api_manager.base_url,
                api_key=SecretStr(self._llm_api_manager.api_key),
            ),
            **config_text["agent"],
        )
        return DefaultAgent.from_config(agent_config)

    def run(self, context: CoderContext, prompt: str) -> bytes | None:
        problem_statement = TextProblemStatement(text=prompt)

        result = self._swe_agent.run(
            problem_statement=problem_statement,
            env=self._swe_environment,
            output_dir=self._session_directory,
        )

        save_predictions(self._session_directory, problem_statement.id, result)

        patch_diff: str | None = result.info.get("submission")  # type: ignore
        context["logger"].info(f"Patch diff: {repr(patch_diff)}")

        if patch_diff is None:
            context["logger"].warning(
                "Failed to extract solution diff from the response message."
            )

        match patch_diff:
            case None:
                return None
            case _:
                return patch_diff.encode()

    def _create_session_directory(self) -> Path:
        if "output_directory" in self._agent_context:
            return self._agent_context["output_directory"]
        else:
            tmp_dir = tempfile.mkdtemp()
            atexit.register(lambda: shutil.rmtree(tmp_dir))
            return Path(tmp_dir)


def _create_swe_agent_environment(challenge_repository: Repo) -> SWEEnv:
    environment_config = EnvironmentConfig(
        deployment=DockerDeploymentConfig(image="python:3.11"),
        repo=LocalRepoConfig(path=Path(challenge_repository.working_dir)),
    )
    return SWEEnv.from_config(environment_config)
