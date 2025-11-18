from crete.framework.agent.services.claude_like import ClaudeLikeAgent
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.crete import Crete
from crete.framework.scheduler.services.round_robin import RoundRobinScheduler


app = Crete(
    id="app-claude-like",
    agents=[
        ClaudeLikeAgent(),
    ],
    scheduler=RoundRobinScheduler(early_exit=True, max_rounds=1),
)

if __name__ == "__main__":
    AIxCCContextBuilder.shell(app)
