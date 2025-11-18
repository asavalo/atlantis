import tempfile
from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.agent.services.vincent.code_inspector import VincentCodeInspector
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment_pool.services.mock import MockEnvironmentPool
from crete.framework.evaluator.services.mock import MockEvaluator

TEST_SNIPPET_DIRECTORY = Path(__file__).parent / "test_snippets"


def _load_test_snippet(target_name: str) -> str:
    with open(TEST_SNIPPET_DIRECTORY / target_name, "r") as f:
        return f.read()


def _test_one_snippet(code_inspector: VincentCodeInspector, target_name: str):
    results = code_inspector.get_definition(target_name)

    assert results is not None
    assert len(results) == 1
    result = results[0]

    # print(result.snippet)

    assert result.snippet.text == _load_test_snippet(target_name)


@pytest.mark.slow
def test_get_definition_class_java(
    detection_jvm_jenkins_cpv_0: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_jvm_jenkins_cpv_0,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_jvm_jenkins_cpv_0),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_jvm_jenkins_cpv_0[0], Path(tmp_dir), "jvm"
        )

        _test_one_snippet(code_inspector, "ParametersTest")
        _test_one_snippet(code_inspector, "ZipArchiverTest")


@pytest.mark.slow
def test_get_definition_interface_java(
    detection_jvm_jenkins_cpv_0: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_jvm_jenkins_cpv_0,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_jvm_jenkins_cpv_0),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_jvm_jenkins_cpv_0[0], Path(tmp_dir), "jvm"
        )

        _test_one_snippet(code_inspector, "AccessControlled")
        _test_one_snippet(code_inspector, "Action")


@pytest.mark.slow
def test_get_definition_annotation_java(
    detection_jvm_jenkins_cpv_0: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_jvm_jenkins_cpv_0,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_jvm_jenkins_cpv_0),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_jvm_jenkins_cpv_0[0], Path(tmp_dir), "jvm"
        )

        _test_one_snippet(code_inspector, "Extension")
        _test_one_snippet(code_inspector, "Initializer")


@pytest.mark.slow
def test_get_definition_enum_java(
    detection_jvm_jenkins_cpv_0: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_jvm_jenkins_cpv_0,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_jvm_jenkins_cpv_0),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_jvm_jenkins_cpv_0[0], Path(tmp_dir), "jvm"
        )

        _test_one_snippet(code_inspector, "VerificationResult")
        _test_one_snippet(code_inspector, "TimeUnit2")


@pytest.mark.slow
def test_get_definition_field_java(
    detection_jvm_jenkins_cpv_0: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_jvm_jenkins_cpv_0,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_jvm_jenkins_cpv_0),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_jvm_jenkins_cpv_0[0], Path(tmp_dir), "jvm"
        )

        _test_one_snippet(code_inspector, "ATOM_COLLECTOR")


@pytest.mark.slow
def test_get_definition_method_java(
    detection_jvm_jenkins_cpv_0: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_jvm_jenkins_cpv_0,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_jvm_jenkins_cpv_0),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_jvm_jenkins_cpv_0[0], Path(tmp_dir), "jvm"
        )

        _test_one_snippet(code_inspector, "respondHello")
        _test_one_snippet(code_inspector, "deleteAllLegacyAndGenerateNewOne")
