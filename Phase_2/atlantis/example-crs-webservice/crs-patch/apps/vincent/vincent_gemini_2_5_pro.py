from crete.framework.agent.services.vincent import VincentAgent
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.crete import Crete
from crete.framework.scheduler.services.round_robin import RoundRobinScheduler
from python_llm.api.actors import LlmApiManager

app = Crete(
    id="app-vincent-gemini-2.5-pro",
    agents=[
        VincentAgent(
            llm_api_manager=LlmApiManager.from_environment(model="gemini-2.5-pro"),
        ),
    ],
    scheduler=RoundRobinScheduler(early_exit=True, max_rounds=1),
)

if __name__ == "__main__":
    AIxCCContextBuilder.shell(app)
