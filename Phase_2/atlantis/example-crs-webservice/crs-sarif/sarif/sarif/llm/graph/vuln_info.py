import re
from typing import Annotated, Literal, Type

from langchain_core.messages import BaseMessage
from langgraph.graph import StateGraph
from pydantic import BaseModel

from sarif.context import SarifCodeContextManager, SarifLLMManager
from sarif.generator.c import TAXA_WHITELIST_C
from sarif.generator.java import TAXA_WHITLELIST_JAVA
from sarif.llm.chat.base import BaseLLM, ask
from sarif.llm.chat.openai import GPT4oLLM
from sarif.llm.prompt.base import BasePrompt
from sarif.llm.prompt.vuln_info import (
    FilterStackTracePrompt,
    GetStackTracePrompt,
    StackTraceModel,
    VulnDescModel,
    VulnDescPrompt,
    VulnRootCauseModel,
    VulnRootCausePrompt,
    VulnTypeModel,
    VulnTypePrompt,
    WrongStackTracePrompt,
)
from sarif.types import PromptOutputT
from sarif.utils.decorators import log_node, read_node_cache, write_node_cache
from sarif.utils.reducers import *


def normalize_whitespace(text: str):
    return " ".join(text.split())


class LocationState(BaseModel):
    file_name: Annotated[str, fixed_value] = ""
    line_number: Annotated[int, fixed_value] = 0
    function_name: Annotated[str, fixed_value] = ""


class PackageState(BaseModel):
    package_language: Annotated[Literal["c", "java"], fixed_value] = "c"
    package_name: Annotated[str, fixed_value] = ""
    package_location: Annotated[str, fixed_value] = ""


class VulnerabilityState(BaseModel):
    vuln_id: Annotated[str, fixed_value] = ""
    sanitizer_output: Annotated[str, fixed_value] = ""


class ConfigState(BaseModel):
    experiment_name: Annotated[str, fixed_value] = ""


class VDState(PackageState, VulnerabilityState, ConfigState):
    last_node: Annotated[str, fixed_value] = ""


class PatchDiffState(BaseModel):
    patch_diff: Annotated[str, fixed_value] = ""


class CrashLocState(LocationState):
    code: Annotated[str, fixed_value] = ""


class StackTraceState(BaseModel):
    crash_stack_trace: Annotated[list[CrashLocState], fixed_value] = []
    memory_allocate_stack_trace: Annotated[list[CrashLocState], fixed_value] = []
    memory_free_stack_trace: Annotated[list[CrashLocState], fixed_value] = []


class VulnBasicInfoState(BaseModel):
    vuln_root_cause: Annotated[str, fixed_value] = ""
    vuln_type: Annotated[str, fixed_value] = ""
    vuln_description: Annotated[str, fixed_value] = ""
    vuln_short_description: Annotated[str, fixed_value] = ""
    vuln_rationale: Annotated[str, fixed_value] = ""


# All
class VulnInfoFinalState(
    VDState, PatchDiffState, StackTraceState, VulnBasicInfoState
): ...


# Input
class InputState(VDState, PatchDiffState): ...


# Output
class OutputState(VulnBasicInfoState, StackTraceState): ...


def generate_vuln_info_graph(
    LLM: Type[BaseLLM[PromptOutputT]] = GPT4oLLM, cached: bool = False
):
    graph_name = "vuln_info"
    graph_builder = StateGraph(VulnInfoFinalState)
    temperature = SarifLLMManager().temperature
    llm: BaseLLM = LLM(temperature=temperature.default)
    from loguru import logger

    def update_stack_trace(state: VulnInfoFinalState, stack_trace: StackTraceModel):
        state.crash_stack_trace = [
            CrashLocState(**t.model_dump()) for t in stack_trace.crash_stack_trace
        ]
        state.memory_allocate_stack_trace = [
            CrashLocState(**t.model_dump())
            for t in stack_trace.memory_allocate_stack_trace
        ]
        state.memory_free_stack_trace = [
            CrashLocState(**t.model_dump()) for t in stack_trace.memory_free_stack_trace
        ]

    def _remove_ansi(text):
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        return ansi_escape.sub("", text)

    def get_only_san_output(state: VulnInfoFinalState):
        crash_log = state.sanitizer_output

        if not crash_log:
            return False

        if "\r\n" in crash_log:
            full_lines = crash_log.split("\r\n")
        else:
            full_lines = crash_log.split("\n")

        # Get the sanitizer output
        start_res = [r"runtime error:", r"ERROR: .+Sanitizer:"]
        end_res = [r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in.+", r"SUMMARY: .+Sanitizer:"]

        start_line = None
        end_line = None

        for idx, line in enumerate(full_lines):
            if start_line == None and any(
                [re.search(start_re, line) for start_re in start_res]
            ):
                start_line = idx
            elif any([re.search(end_re, line) for end_re in end_res]):
                end_line = idx + 1

        if start_line is None or end_line is None:
            return False

        state.sanitizer_output = _remove_ansi(
            "\n".join(full_lines[start_line:end_line])
        )

    def get_stack_trace(state: VulnInfoFinalState, thread: list[BaseMessage]):
        try:
            stack_trace: StackTraceModel = ask(llm, GetStackTracePrompt, state, thread)
        except Exception as e:
            logger.error(f"Error in get_stack_trace: {e}. exiting...")
            raise e
        else:
            update_stack_trace(state, stack_trace)

    def filter_stack_trace(state: VulnInfoFinalState, thread: list[BaseMessage]):
        try:
            stack_trace: StackTraceModel = ask(
                llm, FilterStackTracePrompt, state, thread
            )
        except Exception as e:
            logger.warning(
                f"Error in filter_stack_trace: {e}. Use previous stack trace."
            )
        else:
            update_stack_trace(state, stack_trace)

    def fix_wrong_filename(state: VulnInfoFinalState, thread: list[BaseMessage]):
        wrong_file_names = []
        for trace in (
            state.crash_stack_trace
            + state.memory_allocate_stack_trace
            + state.memory_free_stack_trace
        ):
            # Check the file exist
            try:
                file_location = SarifCodeContextManager().find_file(trace.file_name)
                trace.file_name = file_location
            except Exception as e:
                wrong_file_names.append(trace.file_name)

        if wrong_file_names:
            logger.warning(
                f"[!] Wrong file names: {wrong_file_names} / Vuln. Id: {state.vuln_id}"
            )
            try:
                stack_trace: StackTraceModel = ask(
                    llm,
                    WrongStackTracePrompt,
                    {**state.model_dump(), "wrong_file_names": wrong_file_names},
                    thread,
                )
            except Exception as e:
                logger.warning(
                    f"Error in fix_wrong_filename: {e}. Use previous stack trace."
                )
            else:
                update_stack_trace(state, stack_trace)

    def get_stack_trace_codes(state: VulnInfoFinalState):
        cm = SarifCodeContextManager("C", src_dir=state.package_location)

        def get_stack_trace_code(trace: LocationState):
            file_name, line_number = trace.file_name, trace.line_number
            code_line = cm.get_code_lines(file_name, line_number, line_number)
            code_line = normalize_whitespace(code_line)

            return code_line

        for stack_trace in (
            state.crash_stack_trace
            + state.memory_allocate_stack_trace
            + state.memory_free_stack_trace
        ):
            stack_trace.code = get_stack_trace_code(stack_trace)

    @read_node_cache(
        graph_name=graph_name, cache_model=OutputState, mock=True, enabled=cached
    )
    @log_node(graph_name=graph_name)
    def GetStackTrace(state: VulnInfoFinalState):
        thread = []
        # state = state.copy(deep=True)

        get_only_san_output(state)
        get_stack_trace(state, thread)
        filter_stack_trace(state, thread)
        # fix_wrong_filename(state, thread)
        # get_stack_trace_codes(state)

        return state

    def get_vuln_root_cause(
        state: VulnInfoFinalState, thread: list[BaseMessage], llm: BaseLLM
    ):
        try:
            root_cause: VulnRootCauseModel = ask(
                llm, VulnRootCausePrompt, state, thread
            )
        except Exception as e:
            logger.warning(f"Error in get_vuln_root_cause: {e}. Leave it empty.")
            state.vuln_root_cause = ""
        else:
            state.vuln_root_cause = root_cause.vuln_root_cause

    def get_vuln_type(
        state: VulnInfoFinalState, thread: list[BaseMessage], llm: BaseLLM
    ):
        if state.package_language == "c":
            vuln_type_candidates = TAXA_WHITELIST_C
        else:
            vuln_type_candidates = TAXA_WHITLELIST_JAVA

        try:
            vuln_type: VulnTypeModel = ask(
                llm,
                VulnTypePrompt,
                {
                    **state.model_dump(),
                    "vuln_type_candidates": vuln_type_candidates,
                },
                thread,
            )
        except Exception as e:
            logger.warning(f"Error in get_vuln_type: {e}. Leave it empty.")
            state.vuln_type = ""
        else:
            state.vuln_type = vuln_type.vuln_type

    def get_vuln_desc(
        state: VulnInfoFinalState, thread: list[BaseMessage], llm: BaseLLM
    ):
        try:
            vuln_desc: VulnDescModel = ask(llm, VulnDescPrompt, state, thread)
        except Exception as e:
            logger.warning(f"Error in get_vuln_desc: {e}. Leave it empty.")
            state.vuln_description = ""
            state.vuln_short_description = ""
            state.vuln_rationale = ""
        else:
            state.vuln_description = vuln_desc.vuln_description
            state.vuln_short_description = vuln_desc.vuln_short_description
            state.vuln_rationale = vuln_desc.rationale

    @write_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    @read_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=cached)
    @log_node(graph_name=graph_name)
    def GetVulnBasicInfo(state: VulnInfoFinalState):
        thread = []

        get_vuln_root_cause(state, thread, llm)
        get_vuln_type(state, thread, llm)
        get_vuln_desc(state, thread, llm)

        return state

    # Add nodes
    graph_builder.add_node("vuln_info_stacktrace", GetStackTrace)
    graph_builder.add_node("vuln_info_basic", GetVulnBasicInfo)

    # Set entry and finish points
    graph_builder.set_entry_point("vuln_info_stacktrace")
    graph_builder.set_finish_point("vuln_info_basic")

    # Add edges
    graph_builder.add_edge("vuln_info_stacktrace", "vuln_info_basic")

    return graph_builder.compile()
