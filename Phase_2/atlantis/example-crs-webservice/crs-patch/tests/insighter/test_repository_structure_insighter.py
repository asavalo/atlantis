from pathlib import Path

from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.insighter.services.repository_structure import (
    RepositoryStructureInsighter,
)

from tests.common.utils import mock_insighter_context


def test_mock_cp(detection_c_mock_cp_cpv_1: tuple[Path, Path]):
    expected = r""".gitignore
Makefile
mock_vp.c"""

    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    assert (
        RepositoryStructureInsighter().create(
            mock_insighter_context(context), detection
        )
        == expected
    )


def test_mock_java(detection_jvm_mock_java_cpv_0: tuple[Path, Path]):
    expected = r""".aixcc/
  test.sh
.gitignore
pom.xml
src/
  main/
    java/
      com/
        aixcc/
          mock_java/
            App.java
  test/
    java/
      com/
        aixcc/
          mock_java/
            AppTest.java"""

    context, detection = AIxCCContextBuilder(
        *detection_jvm_mock_java_cpv_0, evaluator=DummyEvaluator()
    ).build(
        previous_action=HeadAction(),
    )

    assert (
        RepositoryStructureInsighter().create(
            mock_insighter_context(context), detection
        )
        == expected
    )
