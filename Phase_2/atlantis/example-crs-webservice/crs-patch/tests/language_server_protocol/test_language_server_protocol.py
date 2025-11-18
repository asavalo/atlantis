from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment_pool.services.mock import MockEnvironmentPool
from crete.framework.evaluator.services.mock import MockEvaluator
from pylspclient.lsp_pydantic_strcuts import Position, Range
from python_oss_fuzz.language_server_protocol.models import Location


def test_c_goto_definitions_same_file(
    detection_c_mock_cp_cpv_1: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_mock_cp_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    defs = context["lsp_client"].goto_definitions(
        file=Path("mock_vp.c"),
        line=11,
        column=17,
    )

    assert defs == [
        Location(
            file=context["pool"].source_directory / "mock_vp.c",
            range=Range(
                start=Position(line=4, character=5),
                end=Position(line=4, character=10),
            ),
        )
    ]


@pytest.mark.slow
def test_c_goto_definitions_other_file(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    defs = context["lsp_client"].goto_definitions(
        file=Path("src/http/modules/ngx_http_userid_filter_module.c"),
        line=423,
        column=14,
    )
    expected_locations = [
        Location(
            file=context["pool"].source_directory / "src/core/ngx_palloc.c",
            range=Range(
                start=Position(line=135, character=0),
                end=Position(line=135, character=11),
            ),
        ),
        Location(
            file=context["pool"].source_directory / "src/core/ngx_palloc.h",
            range=Range(
                start=Position(line=79, character=6),
                end=Position(line=79, character=17),
            ),
        ),
    ]

    assert defs == [expected_locations[0]] or defs == [expected_locations[1]]


def test_java_goto_definitions(
    detection_jvm_mock_java_cpv_0: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_jvm_mock_java_cpv_0,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_jvm_mock_java_cpv_0),
    ).build(
        previous_action=HeadAction(),
    )

    target_file = Path("src/main/java/com/aixcc/mock_java/App.java")

    defs = context["lsp_client"].goto_definitions(
        file=target_file,
        line=15,
        column=13,
    )

    assert defs == [
        Location(
            file=context["pool"].source_directory / target_file,
            range=Range(
                start=Position(line=14, character=27),
                end=Position(line=14, character=41),
            ),
        )
    ]
