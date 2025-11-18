from crete.framework.agent.services.multi_retrieval import MultiRetrievalPatchAgent
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.crete import Crete
from crete.framework.scheduler.services.round_robin import RoundRobinScheduler
from python_llm.api.actors import LlmApiManager

app = Crete(
    id="app-multi-retrieval-claude-3-7",
    agents=[
        MultiRetrievalPatchAgent(
            llm_api_manager=LlmApiManager.from_environment(
                model="claude-3-7-sonnet-20250219",
                custom_llm_provider="anthropic",
            ),
            backup_llm_api_manager=LlmApiManager.from_environment(
                model="gemini-2.5-pro"
            ),
            recursion_limit=256,
            max_n_evals=16,
        ),
    ],
    scheduler=RoundRobinScheduler(early_exit=True, max_rounds=1),
)

if __name__ == "__main__":
    AIxCCContextBuilder.shell(app)
