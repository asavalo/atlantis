import json
from logging import Logger
from langchain_core.messages import BaseMessage, ToolMessage, AIMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import BaseTool, ToolException
from langchain_community.chat_models import ChatLiteLLM
from langgraph.graph import StateGraph, END
from langgraph.graph.state import CompiledStateGraph
from litellm.exceptions import InternalServerError, RateLimitError, Timeout

from tenacity import retry, retry_if_exception_type, wait_exponential

from crete.framework.coder.services.claude_like.states import ClaudeLikeState


class ClaudeLikeGraph:
    def __init__(self, logger: Logger, model: ChatLiteLLM, tools: list[BaseTool]):
        self._logger = logger
        self._tools_by_name = {tool.name: tool for tool in tools}
        self._model = model.bind_tools(tools)  # pyright: ignore[reportUnknownMemberType]

    def construct_graph(self) -> CompiledStateGraph:
        workflow = StateGraph(ClaudeLikeState)

        workflow.add_node("agent", self._call_model)  # pyright: ignore[reportUnknownMemberType]
        workflow.add_node("tools", self._tool_node)  # pyright: ignore[reportUnknownMemberType]

        workflow.set_entry_point("agent")

        workflow.add_conditional_edges(
            "agent",
            self._should_continue,
            {
                "retry": "agent",
                "continue": "tools",
                "end": END,
            },
        )

        workflow.add_edge("tools", "agent")

        graph = workflow.compile()  # type: ignore

        return graph

    def _tool_node(self, state: ClaudeLikeState) -> ClaudeLikeState:
        outputs: list[BaseMessage] = []

        messages = state["messages"]
        last_message = messages[-1]
        assert isinstance(last_message, AIMessage)

        for tool_call in last_message.tool_calls:
            try:
                if tool_call["name"] not in self._tools_by_name:
                    raise ToolException(f"Tool {tool_call['name']} not found")
                tool_result = self._tools_by_name[tool_call["name"]].invoke(  # pyright: ignore[reportUnknownMemberType]
                    tool_call["args"]
                )
            except Exception as e:
                self._logger.info(f"Tool invocation failed: {e}")
                tool_result = str(e)

            outputs.append(
                ToolMessage(
                    content=json.dumps(tool_result),
                    name=tool_call["name"],
                    tool_call_id=tool_call["id"],
                )
            )
        return {"messages": outputs, "retry_model_invoke": False}

    @retry(
        retry=retry_if_exception_type((RateLimitError, InternalServerError, Timeout)),
        wait=wait_exponential(multiplier=1, min=4, max=60),
    )
    def _invoke_model(
        self,
        state: ClaudeLikeState,
        config: RunnableConfig,
    ) -> BaseMessage:
        try:
            response = self._model.invoke(state["messages"], config)
        except (RateLimitError, InternalServerError) as e:
            self._logger.error(f"Model invocation failed (Rate limit): {e}")
            raise
        return response

    def _call_model(
        self,
        state: ClaudeLikeState,
        config: RunnableConfig,
    ) -> ClaudeLikeState:
        try:
            response = self._invoke_model(state, config)
        except Exception as e:
            self._logger.error(f"Model invocation failed (Unknown, retry): {e}")
            return {"messages": state["messages"], "retry_model_invoke": True}
        return {"messages": [response], "retry_model_invoke": False}

    def _should_continue(self, state: ClaudeLikeState) -> str:
        messages = state["messages"]
        last_message = messages[-1]

        if state["retry_model_invoke"]:
            return "retry"

        assert isinstance(last_message, AIMessage)

        if not last_message.tool_calls:
            return "end"
        else:
            return "continue"
