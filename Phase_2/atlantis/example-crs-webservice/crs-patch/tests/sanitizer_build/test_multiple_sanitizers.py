from pathlib import Path
import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder


from crete.framework.environment.exceptions import (
    ChallengePoVFoundError,
)


@pytest.mark.slow
def test_environment_multiple_sanitizers(
    detection_c_faad2_cpv_0: tuple[Path, Path],
    detection_c_faad2_cpv_1: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_faad2_cpv_1,
    ).build(
        previous_action=HeadAction(),
    )

    environment = context["pool"].use(context, "CLEAN")
    assert environment is not None
    environment.restore(context)
    environment.build(context)

    try:
        environment.run_pov(context, detection)
        pytest.fail("Should raise ChallengePoVFoundError")
    except ChallengePoVFoundError as e:
        print(e)
        pass

    context, detection = AIxCCContextBuilder(
        *detection_c_faad2_cpv_0,
    ).build(
        previous_action=HeadAction(),
    )

    environment = context["pool"].use(context, "CLEAN")
    assert environment is not None

    try:
        environment.run_pov(context, detection)
        pytest.fail("Should raise ChallengePoVFoundError")
    except ChallengePoVFoundError as e:
        print(e)
        pass
