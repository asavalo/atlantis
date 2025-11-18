from typing import Annotated, Type

from langgraph.graph import StateGraph
from pydantic import BaseModel

from sarif.context import SarifCodeContextManager, SarifLLMManager
from sarif.llm.chat.base import BaseLLM, ask
from sarif.llm.chat.openai import GPT4oLLM
from sarif.llm.graph.vuln_info import (
    LocationState,
    VulnInfoFinalState,
    generate_vuln_info_graph,
)
from sarif.llm.prompt.sarif import RelatedLocationModel, RelatedLocationPrompt
from sarif.types import PromptOutputT
from sarif.utils.decorators import log_node, write_node_cache
from sarif.utils.reducers import *


class SarifLocationState(LocationState):
    message: Annotated[str, fixed_value] = ""


class RelatedLocationState(BaseModel):
    related_location: Annotated[SarifLocationState, fixed_value] = SarifLocationState()


# All
class SarifFinalState(VulnInfoFinalState, RelatedLocationState): ...


# Input
class InputState(VulnInfoFinalState): ...


# Output
class OutputState(RelatedLocationState): ...


def generate_sarif_graph(
    LLM: Type[BaseLLM[PromptOutputT]] = GPT4oLLM, cached: bool = False
):
    graph_name = "sarif"
    graph = StateGraph(SarifFinalState)
    temperature = SarifLLMManager().temperature
    llm: BaseLLM = LLM(temperature=temperature.default)
    from loguru import logger

    def get_related_location(state: SarifFinalState):
        try:
            related_location: RelatedLocationModel = ask(
                llm,
                RelatedLocationPrompt,
                {
                    **state.model_dump(),
                    "vuln_info": {
                        "root_cause": state.vuln_root_cause,
                        "type": state.vuln_type,
                        "description": state.vuln_description,
                    },
                },
                [],
            )
        except Exception as e:
            logger.error(f"Error in get_related_location: {e}. exiting...")
            raise e
        else:
            state.related_location.function_name = related_location.function_name
            state.related_location.line_number = related_location.line_number
            state.related_location.message = related_location.message
            state.related_location.file_name = related_location.file_name

    @log_node(graph_name=graph_name)
    def GetRelatedLocation(state: SarifFinalState):
        get_related_location(state)
        return state

    # Add nodes
    graph.add_node(
        "vuln_info",
        generate_vuln_info_graph(LLM, cached=cached).with_config(
            {"run_name": "Vuln Info"}
        ),
    )
    graph.add_node("sarif_related_location", GetRelatedLocation)

    # Set entry and finish points
    graph.set_entry_point("vuln_info")
    graph.set_finish_point("sarif_related_location")

    # Add edges
    graph.add_edge("vuln_info", "sarif_related_location")

    return graph.compile()
