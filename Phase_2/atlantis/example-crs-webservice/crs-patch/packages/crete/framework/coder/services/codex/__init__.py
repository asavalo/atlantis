import subprocess
from typing import List
from pathlib import Path

from python_file_system.directory.context_managers import changed_directory
from python_llm.api.actors import LlmApiManager

from crete.atoms.detection import Detection
from crete.commons.interaction.functions import run_command
from crete.framework.agent.contexts import AgentContext
from crete.framework.coder.contexts import CoderContext
from crete.framework.coder.protocols import CoderProtocol


class CodexCoder(CoderProtocol):
    def __init__(
        self,
        agent_context: AgentContext,
        detection: Detection,
        llm_api_manager: LlmApiManager,
    ) -> None:
        super().__init__(agent_context, detection)
        self._llm_api_manager = llm_api_manager

    def run(self, context: CoderContext, prompt: str) -> bytes | None:
        with changed_directory(self._agent_context["pool"].source_directory):
            run_command(("git restore --source=HEAD :/", Path(".")))
            command = self._build_command(prompt)
            try:
                result = subprocess.run(
                    command,
                    check=True,
                    text=True,
                    capture_output=True,
                )
                context["logger"].info(f"codex output:\n{result.stdout}")
            except subprocess.CalledProcessError as e:
                context["logger"].error(f"Error running codex: {e}")
                context["logger"].error(f"codex stderr:\n{e.stderr}")
                return None

            diff = _git_diff().encode()
            context["logger"].info(f"codex diff:\n{diff}")
            return diff

    def _build_command(self, prompt: str) -> List[str]:
        command = ["codex"]
        command.extend(
            [
                "--dangerously-auto-approve-everything",
                "--model",
                self._llm_api_manager.model,
                "--quiet",
            ]
        )
        assert '"' not in prompt, "Prompt should not contain double quotes"
        command.append(f"{prompt}")
        return command


def _git_diff():
    stdout, _ = run_command(("git diff", Path(".")))
    run_command(("git restore --source=HEAD :/", Path(".")))
    return stdout
