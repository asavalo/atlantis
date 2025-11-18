from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment_pool.services.mock import MockEnvironmentPool
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.insighter.services.module_imports import ModuleImportsInsighter


@pytest.mark.slow
def test_module_imports_insighter(
    detection_jvm_oripa_cpv_0: tuple[Path, Path],
):
    expected_import_statements = r"""import java.beans.XMLDecoder;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import oripa.DataSet;
import oripa.doc.Doc;
import oripa.persistence.filetool.FileVersionError;
import oripa.persistence.filetool.WrongDataFormatException;
import oripa.resource.Version;"""

    context, detection = AIxCCContextBuilder(
        *detection_jvm_oripa_cpv_0,
        evaluator=DummyEvaluator(),
        pool=MockEnvironmentPool(*detection_jvm_oripa_cpv_0),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)
    file_path = (
        context["pool"].source_directory
        / "src/main/java/oripa/persistence/doc/loader/LoaderXML.java"
    )
    insighter = ModuleImportsInsighter(file_path)
    actual_import_statements = insighter.create(context, detection)
    assert actual_import_statements == expected_import_statements
