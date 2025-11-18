from crete.framework.agent.services.martian import MartianAgent
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.crete import Crete
from crete.framework.scheduler.services.round_robin import RoundRobinScheduler
from python_llm.api.actors import LlmApiManager

app = Crete(
    id="app-martian-FL-gpt-o4-mini-CG-claude-4",
    agents=[
        MartianAgent(
            fault_localization_llm=LlmApiManager.from_environment(
                model="o4-mini", custom_llm_provider="openai"
            ),
            report_parser_llm=LlmApiManager.from_environment(
                model="gpt-4o", custom_llm_provider="openai"
            ),
            code_generation_llm=LlmApiManager.from_environment(
                model="claude-sonnet-4-20250514", custom_llm_provider="anthropic"
            ),
            backup_llm=LlmApiManager.from_environment(
                model="gemini-2.5-pro",
                custom_llm_provider="openai",
            ),
            max_iterations=5,
        ),
    ],
    scheduler=RoundRobinScheduler(early_exit=True, max_rounds=1),
)
if __name__ == "__main__":
    AIxCCContextBuilder.shell(app)
