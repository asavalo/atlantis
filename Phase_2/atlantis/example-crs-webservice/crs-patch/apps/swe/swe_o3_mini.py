from crete.framework.agent.services.swe import SweAgent
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.crete import Crete
from crete.framework.fault_localizer.services.default import DefaultFaultLocalizer
from crete.framework.scheduler.services.round_robin import RoundRobinScheduler
from python_llm.api.actors import LlmApiManager

app = Crete(
    id="app-swe-o3-mini",
    agents=[
        SweAgent(
            fault_localizer=DefaultFaultLocalizer(),
            llm_api_manager=LlmApiManager.from_environment(model="o3-mini"),
        ),
    ],
    scheduler=RoundRobinScheduler(early_exit=True, max_rounds=1),
)

if __name__ == "__main__":
    AIxCCContextBuilder.shell(app)
