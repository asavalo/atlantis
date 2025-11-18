import re
from typing import Any
from pathlib import Path
from langchain_core.messages import BaseMessage, HumanMessage
from langchain_core.language_models.chat_models import BaseChatModel
from crete.framework.agent.services.vincent.nodes.requests.models import (
    LLMRequest,
    LLMRequestType,
)
from crete.framework.agent.services.vincent.nodes.patchers.models import PatchSegment
from litellm.exceptions import (
    ContextWindowExceededError,
    RateLimitError,
    InternalServerError,
    APIError,
    Timeout,
)
from litellm.utils import encode  # type: ignore
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.functions import store_debug_file
from langchain_core.messages.utils import convert_to_openai_messages  # type: ignore
import json
import time
from crete.atoms.detection import Detection
from crete.framework.analyzer.services.jvm_timeout_stacktrace.functions import (
    get_jvm_timeout_stacktrace,
)
from crete.framework.analyzer.services.jvm_stackoverflow_stacktrace.functions import (
    get_jvm_stackoverflow_stacktrace,
)

PROMPT_DIRECTORY = Path(__file__).parent / "prompts"
TOKEN_LIMIT_WARNING_SIZE = 10000
MAX_TOKEN_RATE_LIMIT_RETRY = 5


def get_token_size(text: str) -> int:
    # @TODO: fix this statement to use each model-specific tokenizer to calculate token size.
    return len(encode(model="gpt-o3-mini", text=text))  # type: ignore


def extract_java_exception_report(full_log: str) -> str | None:
    match = re.search(r"== Java Exception:", full_log)

    if match is None:
        return None

    return full_log[match.start() :]


def extract_sanitizer_report(full_log: str) -> str | None:
    match = re.search(r"==\d+==", full_log)

    if match is None:
        # fail-safe: return the full crash log as it is.
        return full_log

    return full_log[match.start() :]


def filter_crash_log(
    full_log: str, context: AgentContext, detection: Detection
) -> str | None:
    match detection.language:
        case "c" | "c++" | "cpp":
            return extract_sanitizer_report(full_log)
        case "jvm":
            if "ERROR: libFuzzer: timeout" in full_log:
                filtered_log = get_jvm_timeout_stacktrace(context, detection)
            elif "FuzzerSecurityIssueLow: Stack overflow" in full_log:
                filtered_log = get_jvm_stackoverflow_stacktrace(context, detection)
            else:
                filtered_log = extract_java_exception_report(full_log)

            if filtered_log is None:
                return full_log

            return filtered_log


# @TODO: refactor this feature. develop a class that deals with llm interactions, token usage management, and LLM exceptions.
def send_and_update_llm(
    context: AgentContext, messages: list[BaseMessage], llm: BaseChatModel, m: str
):
    msg_token_size = get_token_size(m)
    if msg_token_size > TOKEN_LIMIT_WARNING_SIZE:
        context["logger"].warning(
            f"message token size is larger than {TOKEN_LIMIT_WARNING_SIZE} ({msg_token_size})"
        )
        store_debug_file(
            context,
            f"token-limit-warning-text-{msg_token_size}.txt",
            m,
            log_output=False,
        )

    messages.append(HumanMessage(m))

    for _ in range(MAX_TOKEN_RATE_LIMIT_RETRY):
        try:
            messages.append(llm.invoke(messages))
            return
        except ContextWindowExceededError as e:
            context["logger"].error(
                f"ContextWindowExceededError raised by token size {get_token_size(m)}"
            )

            if "output_directory" in context:
                with open(
                    context["output_directory"]
                    / "context-window-exception-messages.json",
                    "w",
                ) as f:
                    json.dump(convert_to_openai_messages(messages), f)

            raise e
        except (RateLimitError, InternalServerError, APIError, Timeout) as e:
            context["logger"].warning(f"{e} raised, wait for a while...")
            time.sleep(90)
            continue

    raise RuntimeError("Failed to send message to LLM due to the token issue")


def get_last_chat(messages: list[BaseMessage]) -> str:
    return messages[-1].content  # pyright: ignore[reportUnknownMemberType, reportReturnType, reportUnknownVariableType]


def _extract_prompt_args(template: str) -> list[str]:
    pattern = r"\^(.*?)\^"  # find the string: "^SOME_FORMAT_TYPE^"

    return re.findall(pattern, template, re.DOTALL)


def _get_llm_request(request_type: str, raw_request: str) -> LLMRequest:
    if request_type == LLMRequestType.DEFINITION.value:
        request = LLMRequest(
            type=LLMRequestType.DEFINITION,
            targets=_parse_request_target(raw_request, "name"),
            raw=raw_request,
        )
    elif request_type == LLMRequestType.JAVA_DEFINITION.value:
        request = LLMRequest(
            type=LLMRequestType.JAVA_DEFINITION,
            targets=[raw_request],
            raw=raw_request,
        )
    elif request_type == LLMRequestType.REFERENCE.value:
        request = LLMRequest(
            type=LLMRequestType.REFERENCE,
            targets=_parse_request_target(raw_request, "name"),
            raw=raw_request,
        )
    elif request_type == LLMRequestType.RUNTIME_VALUE.value:
        request = LLMRequest(
            type=LLMRequestType.RUNTIME_VALUE,
            targets=[raw_request],
            raw=raw_request,
        )
    elif request_type == LLMRequestType.SHELL.value:
        request = LLMRequest(
            type=LLMRequestType.SHELL,
            targets=_parse_request_target(raw_request, "command"),
            raw=raw_request,
        )
    elif request_type == LLMRequestType.SIMILAR.value:
        request = LLMRequest(
            type=LLMRequestType.SIMILAR,
            targets=_parse_request_target(raw_request, "name"),
            raw=raw_request,
        )
    elif request_type == LLMRequestType.FILE.value:
        request = LLMRequest(
            type=LLMRequestType.FILE,
            targets=_parse_request_target(raw_request, "file"),
            raw=raw_request,
        )
    elif request_type == LLMRequestType.IMPORT.value:
        request = LLMRequest(
            type=LLMRequestType.IMPORT,
            targets=_parse_request_target(raw_request, "name"),
            raw=raw_request,
        )
    elif request_type == LLMRequestType.LINE.value:
        request = LLMRequest(
            type=LLMRequestType.LINE,
            targets=[raw_request],
            raw=raw_request,
        )
    else:
        request = LLMRequest(
            type=LLMRequestType.ERROR,
            targets=[],
            raw=raw_request,
        )

    return request


def extract_requests_in_chat(message: str) -> list[LLMRequest]:
    pattern = r"(?=\[REQUEST:(.*?)\](.*?)\[/REQUEST:\1\])"

    # Use re.search to find the first occurrence of the pattern
    matches = re.findall(pattern, message, re.DOTALL)

    # LLMs can mention the standalone "[REQUEST:type]" somewhere else in the reponse.
    # Although such situation has not been observed yet, prevent the issue in advance.
    innermost_matches: list[Any] = []
    for match in matches:
        # match[1]: raw_request string
        if not any(
            (match[1] != other[1] and other[1] in match[1]) for other in matches
        ):
            innermost_matches.append(match)

    found_requests: list[LLMRequest] = []
    for request_type, raw_request in innermost_matches:
        request_type = request_type.strip()
        raw_request = raw_request.strip()

        request = _get_llm_request(request_type, raw_request)

        found_requests.append(request)

    return found_requests


def extract_patches_from_chat(message: str) -> dict[str, list[PatchSegment]] | None:
    """
    * Example:
    [PATCH:`src/foo.c`:13-18]
    // Patched code
    [/PATCH:`src/foo.c`:13-18]
    """

    pattern = r"(?=(\[PATCH:`(.*?)`:(\d+)-(\d+)\])\n(.*?)\[/PATCH:`\2`:\3-\4\])"

    # Use re.search to find the first occurrence of the pattern
    matches = re.findall(pattern, message, re.DOTALL)

    if len(matches) == 0:
        return None

    results: dict[str, list[PatchSegment]] = {}
    for match in matches:
        patch_tag = match[0]
        filename = match[1].strip()
        start_line = int(match[2])
        end_line = int(match[3])
        patch_code = match[4]

        results.setdefault(filename, []).append(
            PatchSegment(
                patch_tag=patch_tag,
                filename=filename,
                patch_code=patch_code,
                start_line=start_line,
                end_line=end_line,
            )
        )

    # search duplicate tags and remove the invalid segments.
    for filename, patch_segments in results.items():
        results[filename] = sorted(
            _handle_duplicate_patch_tags(patch_segments), key=lambda x: x.start_line
        )

    return results


def _handle_duplicate_patch_tags(
    patch_segments: list[PatchSegment],
) -> list[PatchSegment]:
    found_segments_per_tag: dict[str, list[PatchSegment]] = {}

    for segment in patch_segments:
        found_segments_per_tag.setdefault(segment.patch_tag, []).append(segment)

    for patch_tag, patch_segments in found_segments_per_tag.items():
        if len(patch_segments) == 1:
            continue

        # Find the smallest segment because it must be the real patch segment.
        smallest_segment = patch_segments[0]
        for cur_segment in patch_segments:
            if len(cur_segment.patch_code) < len(smallest_segment.patch_code):
                smallest_segment = cur_segment

        found_segments_per_tag[patch_tag] = [smallest_segment]

    return [
        segment for segments in found_segments_per_tag.values() for segment in segments
    ]


def _parse_request_target(raw_text: str, target_type: str) -> list[str]:
    pattern = rf"\({target_type}:`(.*?)`\)"

    # Use re.search to find the first occurrence of the pattern
    matches = re.findall(pattern, raw_text, re.DOTALL)

    return [match.strip() for match in matches]


def create_prompt(template_name: str, input_args: dict[str, str] = {}) -> str:
    """
    Create prompt using the template in the "prompts" directory (`PROMPT_DIRECTORY`).
    """

    assert PROMPT_DIRECTORY.exists()

    template_path = PROMPT_DIRECTORY / template_name

    if not template_path.exists():
        raise FileNotFoundError(f'"{template_path}" not found')

    # read prompt template file.
    prompt_template = template_path.read_text()

    prompt_args = _extract_prompt_args(prompt_template)

    if len(input_args.keys()) == 0 and len(prompt_args) != 0:
        # template requires some arguements, but the passed argument is empty
        raise ValueError(
            f'prompt template "{prompt_template}" requires arguments, but `args` is not provided'
        )

    # Now fill the arguments of the given prompt template.
    result = prompt_template
    for arg_name in prompt_args:
        if arg_name not in input_args.keys():
            raise ValueError(
                f"prompt template's ^{arg_name}^ is not found in the provided {str(input_args)}"
            )
        result = result.replace(f"^{arg_name}^", input_args[arg_name])

    return result
