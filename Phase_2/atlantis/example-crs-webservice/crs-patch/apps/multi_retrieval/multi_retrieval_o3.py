from crete.framework.agent.services.multi_retrieval import MultiRetrievalPatchAgent
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.crete import Crete
from crete.framework.scheduler.services.round_robin import RoundRobinScheduler
from python_llm.api.actors import LlmApiManager

app = Crete(
    id="app-multi-retrieval-o3",
    agents=[
        MultiRetrievalPatchAgent(
            llm_api_manager=LlmApiManager.from_environment(model="o3"),
            recursion_limit=256,
            max_n_evals=16,
        ),
    ],
    scheduler=RoundRobinScheduler(early_exit=True, max_rounds=1),
)

if __name__ == "__main__":
    AIxCCContextBuilder.shell(app)
