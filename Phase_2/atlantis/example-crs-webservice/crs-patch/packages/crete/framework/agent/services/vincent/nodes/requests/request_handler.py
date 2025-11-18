from typing import Any
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.vincent.nodes.llm_node import LLMNode
from crete.framework.agent.services.vincent.states.patch_state import (
    PatchStage,
    PatchState,
)
from crete.framework.agent.services.vincent.functions import (
    create_prompt,
    extract_requests_in_chat,
    send_and_update_llm,
    get_last_chat,
)
from crete.framework.agent.services.vincent.nodes.requests.models import (
    LLMRequest,
    LLMRequestType,
)
from crete.framework.agent.services.vincent.code_inspector import (
    VincentCodeInspector,
)

from crete.framework.agent.services.vincent.nodes.requests.handlers.definition_handler import (
    DefinitionRequestHandler,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.java_definition_handler import (
    JavaDefinitionRequestHandler,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.reference_handler import (
    ReferenceRequestHandler,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.similar_code_handler import (
    SimilarCodeRequestHandler,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.file_handler import (
    FileRequestHandler,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.runtime_value_handler import (
    RuntimeValueRequestHandler,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.action_handler import (
    ActionRequestHandler,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.import_handler import (
    ImportRequestHandler,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.line_handler import (
    LineRequestHandler,
)
from python_llm.api.actors import LlmApiManager


class RequestHandler(LLMNode):
    def __init__(self, llm_api_manager: LlmApiManager):
        super().__init__(llm_api_manager)
        self.llm_api_manager = llm_api_manager
        self.code_inspector: VincentCodeInspector | None = None
        self.request_history: list[LLMRequest] = []

    def init_handlers(
        self, context: AgentContext, code_inspector: VincentCodeInspector
    ):
        self.context = context
        self.code_inspector = code_inspector

        self.definition_handler = DefinitionRequestHandler(context, self.code_inspector)
        self.java_definition_handler = JavaDefinitionRequestHandler(
            context, self.code_inspector
        )
        self.reference_handler = ReferenceRequestHandler(context, self.code_inspector)
        self.similar_code_handler = SimilarCodeRequestHandler(
            context, self.code_inspector, self.llm_api_manager
        )
        self.file_handler = FileRequestHandler(context)
        # @TODO: This class will handle debugger-related requests.
        self.runtime_value_handler = RuntimeValueRequestHandler(context)
        # @TODO: This class will handle LLM's request that executes arbitrary shell commands.
        self.action_handler = ActionRequestHandler(context)
        self.import_handler = ImportRequestHandler(context)
        self.line_handler = LineRequestHandler(context, self.code_inspector)

    def _handle_request(self, state: PatchState) -> str:
        reply_text = ""
        for request in state.requests:
            self.context["logger"].info(f"handling {request.targets} ({request.type})")

            duplicate_request = self._check_if_request_exists_in_history(request)
            if duplicate_request is not None:
                self.request_history.append(request)
                reply_text += f'The "[REQUEST:{request.type.value}] {request.raw} [/REQUEST:{request.type.value}]" contains the duplicate request with the previous request regarding the target(s): {request.targets}.\nRefer to the previous chat or correct the request if other information is needed.\n\n'
                continue

            match request.type:
                case LLMRequestType.DEFINITION:
                    request_result = self.definition_handler.handle_request(request)
                case LLMRequestType.JAVA_DEFINITION:
                    request_result = self.java_definition_handler.handle_request(
                        request
                    )
                case LLMRequestType.REFERENCE:
                    request_result = self.reference_handler.handle_request(request)
                case LLMRequestType.RUNTIME_VALUE:
                    request_result = self.runtime_value_handler.handle_request(request)
                case LLMRequestType.SHELL:
                    request_result = self.action_handler.handle_request(request)
                case LLMRequestType.SIMILAR:
                    request_result = self.similar_code_handler.handle_request(request)
                case LLMRequestType.FILE:
                    request_result = self.file_handler.handle_request(request)
                case LLMRequestType.IMPORT:
                    request_result = self.import_handler.handle_request(request)
                case LLMRequestType.LINE:
                    request_result = self.line_handler.handle_request(request)
                case LLMRequestType.ERROR:
                    request_result = f'Your request "{request.raw}" does not contain a valid request type. Please check the guideline again and provide a valid request.\n'

            self.request_history.append(request)
            reply_text += request_result

        return reply_text

    def _check_if_request_exists_in_history(
        self, target_request: LLMRequest
    ) -> LLMRequest | None:
        if target_request.targets is None:
            return None

        if len(target_request.targets) == 0:
            return None

        for cur_request in self.request_history:
            if cur_request.type != target_request.type:
                continue
            if cur_request.targets != target_request.targets:
                continue

            return cur_request

        return None

    def __call__(self, state: PatchState) -> dict[str, Any]:
        assert self.code_inspector is not None

        if len(state.requests) == 0:
            # No requests to resolve
            return self._get_dict_from_state(state)

        self.context["logger"].info(
            f"new {len(state.requests)} requests are identified"
        )

        requested_info_result = self._handle_request(state)

        # reply LLM with information feedback
        send_and_update_llm(
            self.context,
            state.messages,
            self.llm,
            create_prompt("request_handler_provide", {"INFO": requested_info_result}),
        )

        state.requests = extract_requests_in_chat(get_last_chat(state.messages))

        return self._get_dict_from_state(state)


def route_request_handler(state: PatchState) -> str:
    if len(state.requests) != 0:
        return "request_handler"

    # no requests
    match state.patch_stage:
        case PatchStage.ANALYZE_ROOT_CAUSE:
            return "root_cause_analyzer"
        case PatchStage.ANALYZE_PROPERTY:
            return "property_analyzer"
        case PatchStage.PATCH:
            return "patcher"
        case PatchStage.COMPILE_FEEDBACK:
            return "compile_feedback"
        case PatchStage.VULNERABLE_FEEDBACK:
            return "vulnerable_feedback"
        case PatchStage.TEST_FEEDBACK:
            return "test_feedback"
        case PatchStage.INIT_ANALYSIS:
            pass
        case PatchStage.DONE:
            pass

    raise ValueError(f"Invalid state {state.patch_stage} in RequestHandler")
