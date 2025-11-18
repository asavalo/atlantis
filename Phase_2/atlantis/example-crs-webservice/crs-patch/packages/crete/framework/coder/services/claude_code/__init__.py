import json
import os
import subprocess
from typing import List
from pathlib import Path

from claude_code import claude_code_path

from python_file_system.directory.context_managers import changed_directory

from crete.atoms.path import PACKAGES_DIRECTORY
from crete.commons.interaction.functions import run_command
from crete.framework.agent.functions import store_debug_file
from crete.framework.coder.contexts import CoderContext
from crete.framework.coder.protocols import CoderProtocol


class ClaudeCodeCoder(CoderProtocol):
    def run(self, context: CoderContext, prompt: str) -> bytes | None:
        self._create_claude_json()
        with changed_directory(self._agent_context["pool"].source_directory):
            run_command(("git restore --source=HEAD :/", Path(".")))
            command = self._build_command()
            try:
                result = subprocess.run(
                    command,
                    check=True,
                    text=True,
                    capture_output=True,
                    input=prompt,
                )
                context["logger"].info(f"claude-code output:\n{result.stdout}")
                store_debug_file(context, "llm_cost.txt", str(self._get_llm_cost()))
            except subprocess.CalledProcessError as e:
                context["logger"].error(f"Error running claude-code: {e}")
                return None

            return _git_diff().encode()

    def _create_claude_json(self) -> None:
        template_path = PACKAGES_DIRECTORY / "claude_code" / "claude.json"
        with open(template_path, "r") as f:
            claude_code_config = json.load(f)

        model_config = {
            "primaryApiKey": os.environ["ANTHROPIC_API_KEY"],
            "projects": {
                f"{self._agent_context['pool'].source_directory}": {
                    "hasTrustDialogAccepted": True,
                    "hasCompletedProjectOnboarding": True,
                    "lastCost": 0,
                }
            },
        }

        claude_code_config.update(model_config)

        with open(Path("~/.claude.json").expanduser(), "w") as f:
            json.dump(claude_code_config, f)

    def _build_command(self) -> List[str]:
        return [
            *claude_code_path(),
            "-p",
            "-ea",
            "-d",
            "--verbose",
            "--dangerously-skip-permissions",
        ]

    def _get_llm_cost(self) -> float:
        with open(Path("~/.claude.json").expanduser(), "r") as f:
            claude_code_config = json.load(f)
            return claude_code_config["projects"][
                f"{self._agent_context['pool'].source_directory}"
            ]["lastCost"]


def _git_diff():
    stdout, _ = run_command(("git diff", Path(".")))
    run_command(("git restore --source=HEAD :/", Path(".")))
    return stdout
