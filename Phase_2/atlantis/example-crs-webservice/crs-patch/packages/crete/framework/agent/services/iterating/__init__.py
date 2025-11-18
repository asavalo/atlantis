from typing import Iterator

from python_llm.api.actors import LlmApiManager

import crete.framework.agent.services.aider as aider
from crete.atoms.action import Action, NoPatchAction
from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.protocols import AgentProtocol
from crete.framework.coder.protocols import CoderProtocol
from crete.framework.coder.services.aider import AiderCoder
from crete.framework.fault_localizer.functions import fault_locations_to_files
from crete.framework.fault_localizer.models import FaultLocation
from crete.framework.fault_localizer.protocols import FaultLocalizerProtocol


class IteratingAgent(AgentProtocol):
    """
    An agent that iterates each fault location and generates a patch for each location.
    The agent expects a fault localizer such as stacktrace-FL, BIC-FL, or call-history-FL.
    """

    def __init__(
        self,
        fault_localizer: FaultLocalizerProtocol,
        llm_api_manager: LlmApiManager,
        coder_name: type[CoderProtocol],
        count: int,
    ) -> None:
        self._fault_localizer = fault_localizer
        self._llm_api_manager = llm_api_manager
        self._coder_name = coder_name
        self._count = count

    def act(self, context: AgentContext, detection: Detection) -> Iterator[Action]:
        fault_locations = self._fault_localizer.localize(context, detection).locations
        for i, fault_location in enumerate(fault_locations):
            if i >= self._count:
                break

            context["logger"].info(f"Fault location: {fault_location}")
            coder = self._load_coder(context, detection, fault_location)
            prompt = self._make_prompt(context, detection, fault_location)
            if "output_directory" in context:
                (context["output_directory"] / f"prompt-{i}.txt").write_text(prompt)

            diff = coder.run(context, prompt)
            if diff is None or len(diff.strip()) == 0:
                yield NoPatchAction()
            else:
                yield context["evaluator"].evaluate(context, diff, detection)

    def _load_coder(
        self,
        context: AgentContext,
        detection: Detection,
        fault_location: FaultLocation,
    ) -> CoderProtocol:
        if self._coder_name == AiderCoder:
            target_files = fault_locations_to_files([fault_location])
            return AiderCoder(context, detection, self._llm_api_manager, target_files)
        else:
            raise NotImplementedError

    def _make_prompt(
        self, context: AgentContext, detection: Detection, fault_location: FaultLocation
    ):
        if self._coder_name == AiderCoder:
            return aider._make_crash_log_prompt(  # pyright: ignore[reportPrivateUsage]
                context, detection, [fault_location], self._llm_api_manager
            )
        else:
            raise NotImplementedError
