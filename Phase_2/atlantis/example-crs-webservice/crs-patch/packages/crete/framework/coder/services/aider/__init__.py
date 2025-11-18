import copy
import difflib
from pathlib import Path
from typing import Any, override

from aider.coders import Coder
from aider.io import InputOutput
from aider.models import MODEL_SETTINGS, Model, ModelSettings
from aider.repo import GitRepo
from python_llm.api.actors import LlmApiManager

from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.coder.contexts import CoderContext
from crete.framework.coder.protocols import CoderProtocol

MODEL_SETTINGS: list[ModelSettings]


class AiderCoder(CoderProtocol):
    def __init__(
        self,
        agent_context: AgentContext,
        detection: Detection,
        llm_api_manager: LlmApiManager,
        target_files: list[Path],
        max_reflections: int = 3,
        use_compile_feedback: bool = False,
    ) -> None:
        super().__init__(agent_context, detection)
        self._llm_api_manager = llm_api_manager

        self._tracker = DiffTracker(
            source_directory=agent_context["pool"].source_directory,
            llm_history_file=_prepare_llm_history_file(agent_context),
        )

        repo = GitRepo(
            io=self._tracker,
            fnames=target_files,
            git_dname=agent_context["pool"].source_directory,
        )

        _extend_model_settings()
        _instrument_for_litellm()

        self._coder = Coder.create(  # pyright: ignore[reportUnknownMemberType]
            main_model=Model(model=f"{llm_api_manager.model}", weak_model=None),
            io=self._tracker,
            repo=repo,
            fnames=target_files,
            auto_commits=False,
            dirty_commits=False,
            map_tokens=0,
            stream=False,
        )
        self._coder.max_reflections = max_reflections
        self._coder.auto_lint = False

        if use_compile_feedback:

            def cmd_test(args: Any):
                diff = self._tracker.git_diff().encode()
                result_action = agent_context["evaluator"].evaluate(
                    agent_context, diff, detection
                )
                from crete.atoms.action import UncompilableDiffAction

                if isinstance(result_action, UncompilableDiffAction):
                    error = result_action.stderr.decode()
                    self._coder.io.tool_output(  # pyright: ignore[reportUnknownMemberType]
                        error
                    )
                    return error

                return None

            self._coder.auto_test = True
            self._coder.test_cmd = ""
            self._coder.commands.cmd_test = (  # pyright: ignore[reportUnknownMemberType]
                cmd_test
            )

    def run(self, context: CoderContext, prompt: str) -> bytes | None:
        context["logger"].debug(f"Prompt:\n{prompt}")
        with self._llm_api_manager.litellm_environment():
            self._coder.run(  # pyright: ignore[reportUnknownMemberType]
                with_message=prompt,
                preproc=False,
            )

        diff = self._tracker.git_diff().encode()
        if diff == b"":
            context["logger"].warning("An unknown error occured in aider")
            return None

        return diff


class DiffTracker(InputOutput):
    def __init__(
        self, source_directory: Path, llm_history_file: Path | None, **kwargs: Any
    ):
        super().__init__(**kwargs)  # pyright: ignore[reportUnknownMemberType]
        self.llm_history_file = llm_history_file
        self.yes = True
        self._source_directory = source_directory

        self._original_contents: dict[str, str] = {}
        self._changes: dict[str, str] = {}

    @override
    def write_text(
        self,
        filename: str,
        content: str,
        max_retries: int = 5,
        initial_delay: float = 0.1,
    ):
        if filename not in self._original_contents:
            self._original_contents[filename] = self.read_text(filename)
        self._changes[filename] = content

    @override
    def read_text(self, filename: str, silent: bool = False) -> str:
        if filename in self._changes:
            return self._changes[filename]
        else:
            text = super().read_text(  # pyright: ignore[reportUnknownMemberType]
                filename
            )
            assert text is not None, f"Unexpected error: {filename}"
            return text

    def git_diff(self) -> str:
        return "".join(
            [
                self._unified_diff_from_change(filename, modified_content)
                for filename, modified_content in self._changes.items()
            ]
        )

    def _unified_diff_from_change(self, filename: str, modified_content: str) -> str:
        original_content = self._original_contents[filename]

        relative_path = Path(filename).relative_to(self._source_directory.resolve())

        # Aider systematically adds a newline at the end of the file.
        # We need to remove it here for proper diffing.
        if not original_content.endswith("\n") and modified_content.endswith("\n"):
            modified_content = modified_content[:-1]

        diff_lines = difflib.unified_diff(
            original_content.splitlines(keepends=True),
            modified_content.splitlines(keepends=True),
            fromfile=f"a/{relative_path}",
            tofile=f"b/{relative_path}",
        )

        validated_diff_lines: list[str] = []
        for line in diff_lines:
            if line.endswith("\n"):
                validated_diff_lines.append(line)
                continue

            # Handle files without trailing newline
            if line.startswith("-"):
                validated_diff_lines.append(line + "\n")
                validated_diff_lines.append("\\ No newline at end of file\n")
            elif line.startswith("+"):
                validated_diff_lines.append(line + "\n")
            elif line.startswith(" "):
                validated_diff_lines.append("-" + line[1:] + "\n")
                validated_diff_lines.append("\\ No newline at end of file\n")
                validated_diff_lines.append("+" + line[1:] + "\n")
            else:
                validated_diff_lines.append(line)

        return "".join(validated_diff_lines)


def _prepare_llm_history_file(context: AgentContext) -> Path | None:
    if "output_directory" in context:
        llm_history_file = context["output_directory"] / ".aider_llm_history_log"
        if llm_history_file.exists():
            llm_history_file.unlink()
            llm_history_file.touch(exist_ok=True)
        return llm_history_file

    return None


def _extend_model_settings():
    model_name_mapping = {
        "openai/gpt-4o": "gpt-4o",
        "openai/gpt-4o-mini": "gpt-4o-mini",
        "openai/o1-mini": "o1-mini",
        "openai/o1-preview": "o1-preview",
        "claude-3-5-sonnet-20241022": "claude-3.5-sonnet",
        "gemini/gemini-2.5-pro-preview-03-25": "gemini-2.5-pro",
    }

    for model_name_in_aider, model_name_in_aixcc in model_name_mapping.items():
        if any(s.name == model_name_in_aixcc for s in MODEL_SETTINGS):  # type: ignore
            continue

        model_setting = copy.deepcopy(  # type: ignore
            next((s for s in MODEL_SETTINGS if s.name == model_name_in_aider))  # type: ignore
        )
        model_setting.name = model_name_in_aixcc
        MODEL_SETTINGS.append(model_setting)  # type: ignore


def _instrument_for_litellm():
    # NOTE: litellm requires gemini models to use openai interface (#883, litellm#7830)
    for model_setting in MODEL_SETTINGS:
        if "gemini" not in model_setting.name:
            continue
        model_setting.extra_params = (model_setting.extra_params or {}) | dict(  # type: ignore
            custom_llm_provider="openai"
        )
