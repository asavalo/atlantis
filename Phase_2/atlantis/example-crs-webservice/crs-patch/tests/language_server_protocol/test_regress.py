from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment_pool.services.mock import MockEnvironmentPool
from crete.framework.evaluator.services.mock import MockEvaluator
from pylspclient.lsp_pydantic_strcuts import Position, Range
from python_oss_fuzz.language_server_protocol.models import Location


@pytest.mark.slow
def test_java_goto_definitions(
    detection_jvm_activemq_cpv_1: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_jvm_activemq_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_jvm_activemq_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    defs = context["lsp_client"].goto_definitions(
        file=Path(
            "activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v4/MarshallerFactory.java"
        ),
        line=67,
        column=16,
    )
    assert defs == [
        Location(
            file=context["pool"].source_directory
            / "activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v4/ExceptionResponseMarshaller.java",
            range=Range(
                start=Position(line=40, character=13),
                end=Position(line=40, character=40),
            ),
        )
    ]
