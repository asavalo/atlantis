from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.code_inspector.functions import (
    get_function_definition_node,
)
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment_pool.services.mock import MockEnvironmentPool
from crete.framework.evaluator.services.mock import MockEvaluator
from crete.framework.language_parser.models import Kind, LanguageNode


@pytest.mark.skip(reason="TODO: fix this test (LSP initialization timeout error)")
def test_get_definition_of_function_node(
    detection_c_mock_cp_cpv_1: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_mock_cp_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    function_node = get_function_definition_node(
        context=context,
        detection=detection,
        file=Path("mock_vp.c"),
        line=33,
        function_name="func_a",
    )
    assert function_node == LanguageNode(
        kind=Kind.FUNCTION,
        start_line=6,
        start_column=0,
        end_line=18,
        end_column=1,
        file=(context["pool"].source_directory / "mock_vp.c"),
        text='void func_a(){\n    char* buff;\n    int i = 0;\n    do{\n        printf("input item:");\n        buff = &items[i][0];\n        i++;\n        fgets(buff, 40, stdin);\n        buff[strcspn(buff, "\\n")] = 0;\n    }while(strlen(buff)!=0);\n    i--;\n}',
    )
