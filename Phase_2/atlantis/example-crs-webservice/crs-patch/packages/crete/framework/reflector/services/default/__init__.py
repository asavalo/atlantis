from litellm.types.utils import Choices, Message, ModelResponse
from python_llm.api.actors import LlmApiManager

from crete.atoms.action import (
    Action,
    CompilableDiffAction,
    UncompilableDiffAction,
    VulnerableDiffAction,
    WrongDiffAction,
)
from crete.framework.reflector.protocols import ReflectorProtocol


class DefaultReflector(ReflectorProtocol):
    def __init__(self, llm_api_manager: LlmApiManager):
        self._llm_api_manager = llm_api_manager

    def reflect(self, previous_actions: list[Action]) -> str | None:
        assert len(previous_actions) >= 1, "Previous actions should not be empty"
        prompt = _action_to_prompt(previous_actions[-1])

        if prompt is None:
            return None

        with (
            self._llm_api_manager.litellm_completion() as completion  # pyright: ignore[reportUnknownVariableType]
        ):
            response = completion(
                messages=[
                    {
                        "role": "user",
                        "content": "You are an experienced programmer. You will be given a previous patch and a hint why the patch is incorrect. Based on this, advise how to write a proper patch. Do not provide the patch itself, but only the advice. Your advice should be clear and concise.\n\n"
                        + prompt,
                    }
                ],
            )

        assert isinstance(response, ModelResponse), "Unreachable code"
        assert isinstance(response.choices[0], Choices), "Failed to get choices."
        assert isinstance(response.choices[0].message, Message), (
            "Failed to get message."
        )

        response_message = response.choices[0].message.content

        assert isinstance(response_message, str), "Failed to get message content."
        return response_message


def _action_to_prompt(action: Action) -> str | None:
    match action:
        case VulnerableDiffAction(diff=diff, stdout=stdout, stderr=stderr):
            return f"- Cause of failure: Your previous code is vulnerable. - Diff: ```diff\n{diff}```\n- Stdout: {stdout.decode()}\n- Stderr: {stderr.decode()}"
        case CompilableDiffAction(diff=diff, stdout=stdout, stderr=stderr):
            return f"- Cause of failure: Your previous code is not functional. - Diff: ```diff\n{diff}```\n- Stdout: {stdout.decode()}\n- Stderr: {stderr.decode()}"
        case UncompilableDiffAction(diff=diff, stdout=stdout, stderr=stderr):
            return f"- Cause of failure: Your previous code is not compilable. - Diff: ```diff\n{diff}```\n- Stdout: {stdout.decode()}\n- Stderr: {stderr.decode()}"
        case WrongDiffAction(diff=diff, stdout=stdout, stderr=stderr):
            return f"- Cause of failure: Your previous code is not a valid format. - Diff: ```diff\n{diff}```\n- Stdout: {stdout.decode()}\n- Stderr: {stderr.decode()}"
        case _:
            # For other actions, we do not use them for reflection.
            return None
