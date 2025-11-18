from pathlib import Path
from typing import cast

from langchain.output_parsers import PydanticOutputParser
from langchain.prompts import ChatPromptTemplate, HumanMessagePromptTemplate
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import SystemMessage
from python_file_system.directory.context_managers import changed_directory

from crete.atoms.detection import Detection
from crete.commons.crash_analysis.functions import get_bug_class
from crete.commons.interaction.functions import run_command
from crete.framework.agent.contexts import AgentContext
from crete.framework.coder.contexts import CoderContext
from crete.framework.coder.protocols import CoderProtocol
from crete.framework.coder.services.redia.models import PatchSet
from crete.framework.environment.functions import resolve_project_path
from crete.framework.insighter.functions import make_relative_to_source_directory
from crete.framework.insighter.services.crash_log import CrashLogInsighter
from crete.framework.insighter.services.stacktrace import StacktraceInsighter


class RediaCoder(CoderProtocol):
    def __init__(
        self,
        agent_context: AgentContext,
        detection: Detection,
        model: BaseChatModel,
        target_files: list[Path],
    ) -> None:
        super().__init__(agent_context, detection)
        self._model = model
        self._target_files = target_files

    def run(self, context: CoderContext, prompt: str) -> bytes | None:
        system_message = SystemMessage(
            content="""You are an expert-level software developer, highly skilled at analyzing and refining source code to ensure functionality and maintainability."""
        )

        files_as_text = "\n".join(
            f"File: {make_relative_to_source_directory(self._agent_context, file)}\nContent:\n```\n{file.read_text(errors='replace')}\n```"
            for file in self._target_files
        )

        human_message_prompt_text_template = prompt

        use_structured_output = (
            self._model.bind_tools  # pyright: ignore[reportUnknownMemberType]
            is not BaseChatModel.bind_tools  # pyright: ignore[reportUnknownMemberType]
        )

        context["logger"].info(f"use_structured_output: {use_structured_output}")

        if use_structured_output:
            parser = None
        else:
            parser = PydanticOutputParser(pydantic_object=PatchSet)

        human_message_prompt_template = HumanMessagePromptTemplate.from_template(
            template=human_message_prompt_text_template
        )

        chat_prompt_template = ChatPromptTemplate.from_messages(  # pyright: ignore[reportUnknownMemberType]
            [
                system_message,
                human_message_prompt_template,
            ]
        )

        chat_prompt = chat_prompt_template.invoke(  # pyright: ignore[reportUnknownMemberType]
            {
                "prompt": self._make_prompt(),
                "files": files_as_text,
                "format_instructions": (
                    parser.get_format_instructions() if parser is not None else ""
                ),
            }
        )

        if use_structured_output:
            patch_set = cast(
                PatchSet,
                self._model.with_structured_output(  # pyright: ignore[reportUnknownMemberType]
                    PatchSet
                ).invoke(chat_prompt),
            )
        else:
            response = self._model.invoke(chat_prompt)
            assert parser is not None, "Unreachable code"
            patch_set = cast(PatchSet, parser.invoke(response))

        with changed_directory(self._agent_context["pool"].source_directory):
            for patched_file in patch_set.patches:
                file_path = resolve_project_path(
                    Path(patched_file.file_path),
                    self._agent_context["pool"].source_directory,
                )

                if file_path is None:
                    self._agent_context["logger"].warning(
                        f"File {patched_file.file_path} does not exist"
                    )
                    continue

                if not file_path.exists():
                    self._agent_context["logger"].warning(
                        f"File {file_path} does not exist"
                    )
                    continue

                original_text = file_path.read_text(errors="replace")
                for replacement in patched_file.replacements:
                    original_text = original_text.replace(
                        replacement.search, replacement.replace
                    )
                file_path.write_text(original_text)

            return _git_diff().encode()

    def _make_prompt(self) -> str:
        bug_class = get_bug_class(self._agent_context, self._detection) or "a"
        prompt = f"# Instruction\nFix {bug_class} vulnerability\n\n"
        prompt += self._get_crash_insight()
        return prompt

    def _get_crash_insight(self) -> str:
        prompt = ""

        crash_log_insight = CrashLogInsighter().create(
            self._agent_context, self._detection
        )
        if crash_log_insight is not None:
            prompt += f"# Crash log\n{crash_log_insight}\n\n"

        stacktrace_insight = StacktraceInsighter().create(
            self._agent_context, self._detection
        )
        if stacktrace_insight is not None:
            prompt += f"# Stack trace that leads to the crash\n{stacktrace_insight}\n\n"

        return prompt


def _git_diff():
    stdout, _ = run_command(("git diff", Path(".")))
    run_command(("git restore --source=HEAD :/", Path(".")))
    return stdout
