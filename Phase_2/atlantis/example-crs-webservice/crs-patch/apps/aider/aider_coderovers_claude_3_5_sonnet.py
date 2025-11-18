from crete.framework.agent.services.aider import AiderAgent
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.crete import Crete
from crete.framework.fault_localizer.services.coderover_k import (
    CodeRoverKFaultLocalizer,
)
from crete.framework.scheduler.services.round_robin import RoundRobinScheduler
from python_llm.api.actors import LlmApiManager

app = Crete(
    id="app-aider-coderovers-claude-3.5-sonnet",
    agents=[
        AiderAgent(
            fault_localizer=CodeRoverKFaultLocalizer(
                analysis_llm=LlmApiManager.from_environment(
                    model="claude-3-5-sonnet-20241022", custom_llm_provider="anthropic"
                ),
                parsing_llm=LlmApiManager.from_environment(
                    model="gpt-4o", custom_llm_provider="openai"
                ),
            ),
            llm_api_manager=LlmApiManager.from_environment(
                model="claude-3-5-sonnet-20241022", custom_llm_provider="anthropic"
            ),
        ),
    ],
    scheduler=RoundRobinScheduler(early_exit=True, max_rounds=1),
)

if __name__ == "__main__":
    AIxCCContextBuilder.shell(app)
