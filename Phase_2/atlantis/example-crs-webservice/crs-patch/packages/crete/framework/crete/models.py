import logging
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from crete.atoms.action import Action, HeadAction, choose_best_action
from crete.atoms.detection import Detection
from crete.atoms.report import CreteResult, result_from_action, store_result
from crete.commons.logging.hooks import use_logger
from crete.commons.tracing import PhoenixTracer
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.protocols import AgentProtocol
from crete.framework.agent.services.claude_code import ClaudeCodeAgent
from crete.framework.context_builder.protocols import ContextBuilderProtocol
from crete.framework.patch_scorer.protocols import PatchScorerProtocol
from crete.framework.reflector.protocols import ReflectorProtocol
from crete.framework.scheduler.contexts import SchedulingContext
from crete.framework.scheduler.models import AgentQueue
from crete.framework.scheduler.protocols import SchedulerProtocol


@dataclass
class Crete:
    id: str
    agents: list[AgentProtocol]
    scheduler: SchedulerProtocol
    reflector: ReflectorProtocol | None = None
    patch_scorer: PatchScorerProtocol | None = None

    _logger: logging.Logger = use_logger()

    def __post_init__(self):
        assert len(self.agents) >= 1, "At least one agent should be provided"
        load_dotenv(override=True)
        PhoenixTracer.setup_from_environment()

    def run(
        self,
        context_builder: ContextBuilderProtocol,
        timeout: int,
        llm_cost_limit: float,
        output_directory: Path | None = None,
    ) -> CreteResult:
        actions_by_agent: AgentQueue = {agent: [HeadAction()] for agent in self.agents}

        scheduling_context: SchedulingContext = {
            "timeout": timeout,
            "llm_cost_limit": llm_cost_limit,
        }

        for agent in self.scheduler.schedule(scheduling_context, self.agents):
            assert agent in actions_by_agent, "Agent should be in the queue"

            actions = actions_by_agent[agent]

            assert len(actions) >= 1, "Actions should not be empty"

            context, detection = context_builder.build(
                previous_action=HeadAction(),  # FIXME: Re-enable reflection
                reflection=self.reflector.reflect(actions) if self.reflector else None,
            )

            action = _run_agent(agent, context, detection)
            self.scheduler.feedback(agent, action)
            actions_by_agent[agent].append(action)

        # Collect LLM cost from ClaudeCodeAgent
        claude_code_llm_cost: float = 0.0
        for agent in self.agents:
            if isinstance(agent, ClaudeCodeAgent):
                claude_code_llm_cost += agent.llm_cost

        actions = [
            action for actions in actions_by_agent.values() for action in actions
        ]
        best_action = choose_best_action(actions)
        result = result_from_action(context_builder, best_action)
        if output_directory:
            store_result(result, output_directory)
            if claude_code_llm_cost > 0:
                (output_directory / "llm_cost.txt").write_text(
                    str(claude_code_llm_cost)
                )
        return result


def _run_agent(
    agent: AgentProtocol, context: AgentContext, detection: Detection
) -> Action:
    actions = list(agent.act(context, detection))
    return choose_best_action(actions)
