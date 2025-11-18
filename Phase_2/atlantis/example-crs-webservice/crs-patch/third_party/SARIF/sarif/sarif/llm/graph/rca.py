from langgraph.graph import StateGraph
from sarif.llm.chat.base import BaseLLM
from sarif.llm.chat.openai import GPT4oLLM
from sarif.llm.graph.root_cause import (
    OutputState,
    PredicateCandidateState,
    RootCauseFinalState,
    generate_root_cause_graph,
)
from sarif.llm.graph.vuln_info import InputState, generate_vuln_info_graph
from sarif.utils.reducers import *


class RCAState(RootCauseFinalState): ...


class InputState(InputState, PredicateCandidateState): ...


class OutputState(OutputState): ...


def generate_rca_graph(
    LLM: BaseLLM = GPT4oLLM,
    cached=False,
):
    graph_name = "rca_graph"
    graph_builder = StateGraph(RCAState)

    graph_builder.add_node("rca_start", lambda state: {"last_node": "rca_start"})
    graph_builder.add_node(
        "vuln_info",
        generate_vuln_info_graph(LLM, cached=cached).with_config(
            {"run_name": "Vuln Info"}
        ),
    )
    graph_builder.add_node(
        "root_cause",
        generate_root_cause_graph(LLM, cached=cached).with_config(
            {"run_name": "Root Cause"}
        ),
    )
    graph_builder.add_node("rca_end", lambda state: {"last_node": "rca_end"})

    graph_builder.set_entry_point("rca_start")
    graph_builder.set_finish_point("rca_end")

    graph_builder.add_edge("rca_start", "vuln_info")
    graph_builder.add_edge("vuln_info", "root_cause")
    graph_builder.add_edge("root_cause", "rca_end")

    return graph_builder.compile()
