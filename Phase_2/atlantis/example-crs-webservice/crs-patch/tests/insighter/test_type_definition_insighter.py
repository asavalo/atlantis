from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment_pool.services.mock import MockEnvironmentPool
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.insighter.services.type_definition import TypeDefinitionInsighter
from crete.framework.language_parser.functions import get_declaration_by_line

from tests.common.utils import mock_insighter_context


@pytest.mark.vcr()
def test_mock_cp(
    detection_c_mock_cp_cpv_1: tuple[Path, Path],
):
    expected_insight = r"""Variables in method: func_a
Variables declarations:
- name: buff, type: char *
- name: i, type: int
"""

    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DummyEvaluator(),
        pool=MockEnvironmentPool(*detection_c_mock_cp_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    target_function = get_declaration_by_line(
        context["language_parser"],
        context,
        context["pool"].source_directory / "mock_vp.c",
        7,
    )
    assert target_function is not None, "Target function not found"

    insight = TypeDefinitionInsighter(target_function).create(  # type: ignore
        mock_insighter_context(context), detection
    )
    assert insight == expected_insight
