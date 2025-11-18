from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.insighter.services.folded_code import FoldedCodeInsighter

from tests.common.utils import mock_insighter_context


def test_mock_cp(detection_c_mock_cp_cpv_1: tuple[Path, Path]):
    expected = r"""### File: mock_vp.c

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

char items[3][10];

void func_a(){...}

void func_b(){...}

#ifndef ___TEST___
int main()
{...}
#endif

```
"""

    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    assert (
        FoldedCodeInsighter(context["pool"].source_directory / "mock_vp.c").create(
            mock_insighter_context(context), detection
        )
        == expected
    )


@pytest.mark.regression
@pytest.mark.slow
def test_cp_java_ztzip(detection_jvm_ztzip_cpv_0: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_jvm_ztzip_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    # Should not raise an error
    FoldedCodeInsighter(
        context["pool"].source_directory
        / "src/main/java/org/zeroturnaround/zip/ZipUtil.java"
    ).create(mock_insighter_context(context), detection)
