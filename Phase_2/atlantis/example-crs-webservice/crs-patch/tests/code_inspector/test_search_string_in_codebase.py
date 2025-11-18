from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.code_inspector.functions import search_string_in_source_directory
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment_pool.services.mock import MockEnvironmentPool
from crete.framework.evaluator.services.mock import MockEvaluator


@pytest.mark.slow
def test_search_string_in_source_directory_success(
    detection_jvm_jenkins_cpv_0: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_jvm_jenkins_cpv_0,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_jvm_jenkins_cpv_0),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    results = search_string_in_source_directory(
        context["pool"].source_directory,
        "createUtils",
    )
    context["logger"].info(results)
    assert set(results) == set(
        [
            (
                context["pool"].source_directory
                / "plugins/pipeline-util-plugin/src/main/java/io/jenkins/plugins/UtilPlug/UtilMain.java",
                156,
                "                String res_match = createUtils(cmdSeq2);",
            ),
            (
                context["pool"].source_directory
                / "plugins/pipeline-util-plugin/src/main/java/io/jenkins/plugins/UtilPlug/UtilMain.java",
                166,
                "            String res_auth = createUtils(cmdSeq2);",
            ),
            (
                context["pool"].source_directory
                / "plugins/pipeline-util-plugin/src/main/java/io/jenkins/plugins/UtilPlug/UtilMain.java",
                181,
                "    String createUtils(String cmd) throws BadCommandException {",
            ),
        ]
    )


@pytest.mark.slow
def test_search_string_in_source_directory_not_found(
    detection_jvm_oripa_cpv_0: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_jvm_oripa_cpv_0,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_jvm_oripa_cpv_0),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    results = search_string_in_source_directory(
        context["pool"].source_directory,
        "LoaderXML.java",
    )
    assert results == []
