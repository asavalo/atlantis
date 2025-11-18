from pathlib import Path

from crete.atoms.action import HeadAction
from crete.atoms.detection import Detection
from crete.framework.agent.services.aider import AiderAgent
from crete.framework.agent.services.aider import (
    _make_crash_log_prompt as make_aider_prompt,  # pyright: ignore[reportPrivateUsage]
)
from crete.framework.agent.services.swe import SweAgent
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.fault_localizer.contexts import FaultLocalizationContext
from crete.framework.fault_localizer.models import (
    FaultLocalizationResult,
    FaultLocation,
)
from crete.framework.fault_localizer.protocols import FaultLocalizerProtocol
from python_llm.api.actors import LlmApiManager


class MockFaultLocalizer(FaultLocalizerProtocol):
    def localize(
        self,
        context: FaultLocalizationContext,
        detection: Detection,
    ) -> FaultLocalizationResult:
        return FaultLocalizationResult(
            locations=[
                FaultLocation(
                    context["pool"].source_directory / "mock_vp.c",
                    "func_a",
                    (14, 14),
                )
            ]
        )


def test_aider(detection_c_mock_cp_cpv_0: tuple[Path, Path]):
    prompt_fl = """Fix AddressSanitizer: global-buffer-overflow vulnerability from below locations:
file: mock_vp.c function: func_a line: 14:14"""

    agent = AiderAgent(
        fault_localizer=MockFaultLocalizer(),
        llm_api_manager=LlmApiManager.from_environment(model="gpt-4o"),
    )

    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    prompt = make_aider_prompt(  # pyright: ignore[reportPrivateUsage]
        context,
        detection,
        agent._fault_localizer.localize(  # pyright: ignore[reportPrivateUsage]
            context, detection
        ).locations,
        agent._llm_api_manager,  # pyright: ignore[reportPrivateUsage]
    )

    assert prompt.startswith(prompt_fl)


def test_swe(detection_c_mock_cp_cpv_0: tuple[Path, Path]):
    prompt_fl = """Fix AddressSanitizer: global-buffer-overflow vulnerability from below locations.

file: mock_vp.c function: func_a line: 14:14"""

    agent = SweAgent(
        fault_localizer=MockFaultLocalizer(),
        llm_api_manager=LlmApiManager.from_environment(model="gpt-4o"),
    )

    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    fault_locations = agent._fault_localizer.localize(  # pyright: ignore[reportPrivateUsage]
        context, detection
    ).locations
    relative_fault_locations = agent._strip_fault_locations(  # pyright: ignore[reportPrivateUsage]
        context, fault_locations
    )

    prompt = agent._make_base_prompt(  # pyright: ignore[reportPrivateUsage]
        context,
        detection,
        relative_fault_locations,
    )
    print(prompt)
    assert prompt.startswith(prompt_fl)
