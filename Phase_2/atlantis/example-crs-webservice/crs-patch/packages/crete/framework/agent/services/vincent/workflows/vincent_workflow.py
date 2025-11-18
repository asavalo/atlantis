from typing import Any
from langchain_core.runnables.config import RunnableConfig
from langgraph.graph import (  # pylint: disable=import-error, no-name-in-module
    START,
    StateGraph,
)
from langgraph.graph.state import (
    CompiledStateGraph,  # pylint: disable=import-error, no-name-in-module
)

from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext

from crete.framework.agent.services.vincent.nodes.analyzers.init_analyzer import (
    InitAnalyzer,
)

from crete.framework.agent.services.vincent.nodes.analyzers.root_cause_analyzer import (
    RootCauseAnalyzer,
    route_root_cause_analyzer,
)

from crete.framework.agent.services.vincent.nodes.analyzers.property_analyzer import (
    PropertyAnalyzer,
    route_property_analyzer,
)

from crete.framework.agent.services.vincent.nodes.requests.request_handler import (
    RequestHandler,
    route_request_handler,
)
from crete.framework.agent.services.vincent.nodes.patchers.patcher import (
    Patcher,
    route_patcher,
)
from crete.framework.agent.services.vincent.nodes.patchers.compile_feedback import (
    CompileFeedbackPatcher,
    route_compile_feedback_patcher,
)
from crete.framework.agent.services.vincent.nodes.patchers.vulnerable_feedback import (
    VulnerableFeedbackPatcher,
    route_vulnerable_feedback_patcher,
)
from crete.framework.agent.services.vincent.nodes.patchers.test_feedback import (
    TestFeedbackPatcher,
    route_test_feedback_patcher,
)
from crete.framework.agent.services.vincent.states.patch_state import (
    PatchState,
)
from python_llm.api.actors import LlmApiManager
from crete.atoms.path import DEFAULT_CACHE_DIRECTORY
from os.path import basename
from crete.framework.agent.services.vincent.code_inspector import (
    VincentCodeInspector,
)

VINCENT_CACHE_DIRECTORY = DEFAULT_CACHE_DIRECTORY / "vincent"


class VincentWorkflow:
    def __init__(
        self,
    ) -> None:
        super().__init__()
        self._compiled_graph: CompiledStateGraph | None = None

    @property
    def compiled_graph(self) -> CompiledStateGraph:
        if self._compiled_graph is None:
            raise ValueError("Workflow is not compiled. Please call compile() first.")
        return self._compiled_graph

    def compile(  # pylint: disable=arguments-differ
        self,
        llm_api_manager: LlmApiManager,
    ) -> None:
        self.init_analyzer = InitAnalyzer(llm_api_manager=llm_api_manager)
        self.root_cause_analyzer = RootCauseAnalyzer(llm_api_manager=llm_api_manager)
        self.property_analyzer = PropertyAnalyzer(llm_api_manager=llm_api_manager)
        self.request_handler = RequestHandler(llm_api_manager=llm_api_manager)
        self.patcher = Patcher(llm_api_manager=llm_api_manager)
        self.compile_feedback = CompileFeedbackPatcher(llm_api_manager=llm_api_manager)
        self.vulnerable_feedback = VulnerableFeedbackPatcher(
            llm_api_manager=llm_api_manager
        )
        self.test_feedback = TestFeedbackPatcher(llm_api_manager=llm_api_manager)
        graph_builder = StateGraph(PatchState)  # type: ignore

        graph_builder.add_node("init_analyzer", self.init_analyzer)  # type: ignore
        graph_builder.add_node("root_cause_analyzer", self.root_cause_analyzer)  # type: ignore
        graph_builder.add_node("property_analyzer", self.property_analyzer)  # type: ignore
        graph_builder.add_node("patcher", self.patcher)  # type: ignore
        graph_builder.add_node("compile_feedback", self.compile_feedback)  # type: ignore
        graph_builder.add_node("vulnerable_feedback", self.vulnerable_feedback)  # type: ignore
        graph_builder.add_node("test_feedback", self.test_feedback)  # type: ignore
        graph_builder.add_node("request_handler", self.request_handler)  # type: ignore

        graph_builder.add_edge(START, "init_analyzer")
        graph_builder.add_edge("init_analyzer", "root_cause_analyzer")

        graph_builder.add_conditional_edges(
            "root_cause_analyzer", route_root_cause_analyzer
        )
        graph_builder.add_conditional_edges(
            "property_analyzer", route_property_analyzer
        )
        graph_builder.add_conditional_edges("patcher", route_patcher)
        graph_builder.add_conditional_edges(
            "compile_feedback", route_compile_feedback_patcher
        )
        graph_builder.add_conditional_edges(
            "vulnerable_feedback", route_vulnerable_feedback_patcher
        )
        graph_builder.add_conditional_edges(
            "test_feedback", route_test_feedback_patcher
        )
        graph_builder.add_conditional_edges("request_handler", route_request_handler)

        self._compiled_graph = graph_builder.compile()  # type: ignore

        # self._compiled_graph.get_graph().draw_mermaid_png(output_file_path='/tmp/graph.png')

    def invoke(self, state: PatchState, config: RunnableConfig) -> dict[str, Any] | Any:
        return self.compiled_graph.invoke(state, config)

    def update(self, context: AgentContext, detection: Detection):
        self.init_analyzer.set_context(context)
        self.root_cause_analyzer.set_context(context)
        self.property_analyzer.set_context(context)
        self.request_handler.set_context(context)
        self.patcher.set_context_and_detection(context, detection)
        self.compile_feedback.set_context_and_detection(context, detection)
        self.vulnerable_feedback.set_context_and_detection(context, detection)
        self.test_feedback.set_context_and_detection(context, detection)

        if not VINCENT_CACHE_DIRECTORY.exists():
            VINCENT_CACHE_DIRECTORY.mkdir()

        cache_dir = (
            VINCENT_CACHE_DIRECTORY
            / f"{basename(context['pool'].source_directory)}.cache"
        )

        if not cache_dir.exists():
            cache_dir.mkdir()

        code_inspector = VincentCodeInspector(
            context["pool"].source_directory, cache_dir, detection.language
        )
        self.init_analyzer.set_code_inspector(code_inspector)
        self.request_handler.init_handlers(context, code_inspector)

    def router_node(
        self,
        state: PatchState,  # pylint: disable=unused-argument
    ) -> dict[str, Any]:
        return {}
