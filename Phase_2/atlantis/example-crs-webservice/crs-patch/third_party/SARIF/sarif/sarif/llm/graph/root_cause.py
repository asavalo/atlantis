from functools import partial
from typing import Annotated, List, Type

from langgraph.graph import StateGraph
from pydantic import BaseModel

from sarif.context import SarifCodeContextManager, SarifLLMManager
from sarif.llm.chat.base import BaseLLM, ask
from sarif.llm.chat.openai import GPT4oLLM
from sarif.llm.graph.vuln_info import CrashLocState, LocationState, VulnInfoFinalState
from sarif.llm.prompt.root_cause import (
    EvalRootCauseModel,
    EvalRootCausePrompt,
    SelectRootCauseBranchPrompt,
    SelectRootCauseModel,
)
from sarif.types import PromptOutputT
from sarif.utils.decorators import log_node, write_node_cache
from sarif.utils.reducers import *


def normalize_whitespace(text: str):
    return " ".join(text.split())


MAX_DISTANCE = 50
MAX_RESULT = 3


class PredicateState(LocationState):
    id: Annotated[int, fixed_value] = 0
    rank: Annotated[int, fixed_value] = 0
    score: Annotated[float, fixed_value] = 0.0
    code_line: Annotated[str, fixed_value] = ""


class PredicateCandidateState(BaseModel):
    predicate_candidates: Annotated[list[PredicateState], fixed_value] = []


class CrashAndPredicateState(BaseModel):
    crash_loc: Annotated[CrashLocState, fixed_value] = CrashLocState()
    predicates: Annotated[list[PredicateState], fixed_value] = []
    code: Annotated[str, fixed_value] = ""


class RootCauseState(PredicateState):
    crash_loc: Annotated[CrashLocState, fixed_value] = CrashLocState()

    # Select
    select_rationale: Annotated[str, fixed_value] = ""

    # Eval
    score: Annotated[float, fixed_value] = 0.0
    confidence: Annotated[float, fixed_value] = 0.0
    reliability_score: Annotated[float, fixed_value] = 0.0
    eval_rationale: Annotated[str, fixed_value] = ""


class FinalRootCauseState(BaseModel):
    crash_and_predicates: Annotated[list[CrashAndPredicateState], fixed_value] = []
    root_cause_candidates: Annotated[list[RootCauseState], fixed_value] = []
    results: Annotated[list[RootCauseState], fixed_value] = []


# All
class RootCauseFinalState(VulnInfoFinalState, FinalRootCauseState): ...


# Input
class InputState(VulnInfoFinalState): ...


# Output
class OutputState(FinalRootCauseState): ...


def generate_root_cause_graph(
    LLM: Type[BaseLLM[PromptOutputT]] = GPT4oLLM, cached: bool = False
):
    graph_name = "root_cause"
    graph = StateGraph(RootCauseFinalState)
    temperature = SarifLLMManager().temperature
    llm: BaseLLM = LLM(temperature=temperature.default)
    from loguru import logger

    def get_predicates_by_crash_loc(
        predicates: List[PredicateState], crash_loc: CrashLocState
    ):
        selected_predicates = []

        for predicate in predicates:
            if (
                predicate.file_name == crash_loc.file_name.split("/")[-1]
                and abs(predicate.line_number - crash_loc.line_number) < MAX_DISTANCE
            ):
                selected_predicates.append(predicate)

        return selected_predicates

    def get_crash_and_predicates(state: RootCauseFinalState):
        cm = SarifCodeContextManager()

        for crash_loc in state.crash_stack_trace:
            crash_and_predicate = CrashAndPredicateState(crash_loc=crash_loc)
            crash_and_predicate.predicates = get_predicates_by_crash_loc(
                state.predicate_candidates, crash_loc
            )

            if len(crash_and_predicate.predicates) == 0:
                logger.warning(f"No predicates found for crash location {crash_loc}")
                continue

            # Get code from crash loc and annotate crash location
            crash_and_predicate.crash_loc.code = cm.get_code_block(
                crash_loc.file_name,
                crash_loc.line_number,
                min_line=MAX_DISTANCE,
                max_line=MAX_DISTANCE * 2,
            )

            for predicate in crash_and_predicate.predicates:
                predicate.code_line = cm.get_code_lines(
                    predicate.file_name,
                    predicate.line_number,
                    predicate.line_number,
                )

                # Annotate predicate location
                replace_line = predicate.code_line
                if replace_line in crash_and_predicate.crash_loc.code:
                    # If replace_line is found multiple times, log warning
                    if crash_and_predicate.crash_loc.code.count(replace_line) > 1:
                        logger.warning(
                            f"Multiple predicate lines found for {predicate}"
                        )

                    predicate_annotated = f"// Root cause candidate ID {predicate.id} (rank: {predicate.rank}, score: {predicate.score}).\n{replace_line}"
                    crash_and_predicate.crash_loc.code = (
                        crash_and_predicate.crash_loc.code.replace(
                            replace_line, predicate_annotated
                        )
                    )

            # Annotate crash location
            replace_line = cm.get_code_lines(
                crash_loc.file_name,
                crash_loc.line_number,
                crash_loc.line_number,
            )
            if replace_line in crash_and_predicate.crash_loc.code:
                # If replace_line is found multiple times, log warning
                if crash_and_predicate.crash_loc.code.count(replace_line) > 1:
                    logger.warning(f"Multiple crash lines found for {crash_loc}")

                # crash_annotated = f"// Crash {state.vuln_type}.\nOriginal loc: {crash_and_predicate.crash_loc.file_name}@{crash_and_predicate.crash_loc.line_number} at function {crash_and_predicate.crash_loc.function_name}\n{replace_line}"
                crash_annotated = f"// Crash {state.vuln_type}.\n{replace_line}"
                crash_and_predicate.crash_loc.code = (
                    crash_and_predicate.crash_loc.code.replace(
                        replace_line, crash_annotated
                    )
                )

            crash_and_predicate.code = crash_and_predicate.crash_loc.code
            state.crash_and_predicates.append(crash_and_predicate)

    def select_root_cause_candidates(state: RootCauseFinalState):
        BRANCH_NUM = 3

        prompt_cls = partial(SelectRootCauseBranchPrompt, branch_num=BRANCH_NUM)

        for crash_and_predicate in state.crash_and_predicates:
            try:
                selected_root_cause: SelectRootCauseModel = ask(
                    llm, SelectRootCauseBranchPrompt, crash_and_predicate, []
                )
            except Exception as e:
                logger.error(f"Error in select_root_cause_candidates: {e}. exiting...")
                raise e
            else:
                for i in range(1, BRANCH_NUM + 1):
                    root_cause_id: int = selected_root_cause.__getattribute__(
                        f"root_cause_id_{i}"
                    )
                    select_rationale: str = selected_root_cause.__getattribute__(
                        f"select_rationale_{i}"
                    )

                    selected_predicate = state.predicate_candidates[root_cause_id]
                    root_cause = RootCauseState(**selected_predicate.model_dump())
                    root_cause.crash_loc = crash_and_predicate.crash_loc
                    root_cause.select_rationale = select_rationale
                    state.root_cause_candidates.append(root_cause)

    @log_node(graph_name=graph_name)
    def SelectRootCauseCandidates(state: RootCauseFinalState):
        get_crash_and_predicates(state)
        select_root_cause_candidates(state)
        return state

    def evaluate_root_cause_candidates(state: RootCauseFinalState):
        for root_cause in state.root_cause_candidates:
            try:
                root_cause_score: EvalRootCauseModel = ask(
                    llm,
                    EvalRootCausePrompt,
                    {
                        **root_cause.model_dump(),
                        "vuln_type": state.vuln_type,
                        "vuln_description": state.vuln_description,
                        "sanitizer_output": state.sanitizer_output,
                    },
                    [],
                )
            except Exception as e:
                logger.error(
                    f"Error in evaluate_root_cause_candidates: {e}. exiting..."
                )
                raise e
            else:
                root_cause.score = root_cause_score.score
                root_cause.confidence = root_cause_score.confidence
                # TODO: Use reliability score??
                # root_cause.reliability_score = root_cause_score.score * (
                #     1 + 0.1 * root_cause_score.confidence
                # )
                root_cause.eval_rationale = root_cause_score.eval_rationale

    def select_top_K(state: RootCauseFinalState):
        state.results = sorted(
            state.root_cause_candidates, key=lambda x: x.score, reverse=True
        )[:MAX_RESULT]

    @write_node_cache(graph_name=graph_name, cache_model=OutputState, enabled=True)
    @log_node(graph_name=graph_name)
    def EvalRootCauseCandidates(state: RootCauseFinalState):
        evaluate_root_cause_candidates(state)
        select_top_K(state)
        return state

    # Add nodes
    graph.add_node("root_cause_select", SelectRootCauseCandidates)
    graph.add_node("root_cause_eval", EvalRootCauseCandidates)

    # Set entry and finish points
    graph.set_entry_point("root_cause_select")
    graph.set_finish_point("root_cause_eval")

    # Add edges
    graph.add_edge("root_cause_select", "root_cause_eval")

    return graph.compile()
