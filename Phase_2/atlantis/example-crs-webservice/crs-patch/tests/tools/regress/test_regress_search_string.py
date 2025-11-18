from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.mock import MockEvaluator
from crete.framework.tools.services import SearchStringTool


@pytest.mark.slow
def test_regress_search_string_1(
    detection_c_r2_sqlite3_cpv_1: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_c_r2_sqlite3_cpv_1,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    string = "shell_main("
    ret = SearchStringTool(context, context["pool"].source_directory)._run(string)  # type: ignore

    context["logger"].info(ret)
    assert "test/shell.h:1:int shell_main(int argc, char **argv);" in ret
    assert "test/customfuzz3.c:27:  shell_main(argc, shellCmd);" in ret
