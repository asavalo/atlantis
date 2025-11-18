from crete.framework.agent.services.eraser import AdaptationClient, EraserAgent
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.crete.models import Crete
from crete.framework.scheduler.services.round_robin import RoundRobinScheduler
from p4 import (
    CppCallPattern,
    CppFunctionDefinitionTool,
    CppTypeDefinitionTool,
    CppTypeIdentifierPattern,
    JavaInvocationPattern,
    JavaMethodDeclarationTool,
    JazzerFunctionSignaturePattern,
    SanitizerFunctionSignaturePattern,
)
from python_llm.api.actors import LlmApiManager

app = Crete(
    id="app-eraser",
    agents=[
        EraserAgent(
            adaptation_client=AdaptationClient.from_environment(),
            tools=[
                CppTypeDefinitionTool(),
                JavaMethodDeclarationTool(),
                CppFunctionDefinitionTool(),
            ],
            patterns=[
                CppCallPattern(limit=None),
                CppTypeIdentifierPattern(limit=None),
                JavaInvocationPattern(limit=None),
                JazzerFunctionSignaturePattern(limit=16),
                SanitizerFunctionSignaturePattern(limit=8),
            ],
            episode_length=4,
            llm_api_manager_for_patching=LlmApiManager.from_environment(
                model="gpt-4.1"
            ),
            fallback_llm_api_manager_for_retrieval=LlmApiManager.from_environment(
                model="meta-llama/Llama-3.2-3B-Instruct",
                key_of_base_url="VLLM_API_BASE",
            ),
        )
    ],
    scheduler=RoundRobinScheduler(early_exit=True, max_rounds=12),
)

if __name__ == "__main__":
    AIxCCContextBuilder.shell(app)
