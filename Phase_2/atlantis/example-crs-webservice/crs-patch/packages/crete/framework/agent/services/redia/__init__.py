from typing import Iterator

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.runnables.config import RunnableConfig
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from python_llm.api.actors import LlmApiManager

from crete.atoms.action import Action, HeadAction
from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.protocols import AgentProtocol
from crete.framework.agent.services.redia.nodes import (
    RediaCoderNode,
    RediaEvaluatorNode,
    RediaFaultLocalizerNode,
    evaluator_condition,
)
from crete.framework.agent.services.redia.states import RediaState
from crete.framework.fault_localizer.protocols import FaultLocalizerProtocol


class RediaAgent(AgentProtocol):
    def __init__(
        self,
        fault_localizer: FaultLocalizerProtocol,
        llm_api_manager: LlmApiManager,
    ) -> None:
        self._fault_localizer = fault_localizer
        self._llm_api_manager = llm_api_manager

    def act(self, context: AgentContext, detection: Detection) -> Iterator[Action]:
        self._graph: CompiledStateGraph = self._create_graph(
            context, detection, self._llm_api_manager.langchain_litellm()
        )
        config: RunnableConfig = {"configurable": {"thread_id": "1"}}
        initial_state: RediaState = {
            "messages": [],
            "target_files": [],
            "diff": b"",
            "action": HeadAction(),
        }

        events = self._graph.stream(
            initial_state,
            config,
            stream_mode="values",
        )

        for event in events:
            last_action: Action = event["action"]
        yield last_action  # pyright: ignore[reportPossiblyUnboundVariable]

    def _create_graph(
        self, context: AgentContext, detection: Detection, chat_model: BaseChatModel
    ) -> CompiledStateGraph:
        graph_builder = StateGraph(RediaState)

        graph_builder.add_node(  # pyright: ignore[reportUnknownMemberType]
            "fault_localizer",
            RediaFaultLocalizerNode(context, detection, self._fault_localizer),
        )
        graph_builder.add_node(  # pyright: ignore[reportUnknownMemberType]
            "coder",
            RediaCoderNode(context, detection, chat_model),
        )
        graph_builder.add_node(  # pyright: ignore[reportUnknownMemberType]
            "evaluator",
            RediaEvaluatorNode(context, detection),
        )

        graph_builder.add_edge(START, "fault_localizer")
        graph_builder.add_edge("fault_localizer", "coder")
        graph_builder.add_edge("coder", "evaluator")
        graph_builder.add_conditional_edges(
            "evaluator",
            evaluator_condition,
        )

        memory = MemorySaver()
        return graph_builder.compile(  # pyright: ignore[reportUnknownMemberType]
            checkpointer=memory
        )
