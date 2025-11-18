from contextlib import contextmanager
from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.agent.contexts import AgentContext
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.mock import MockEvaluator
from crete.framework.tools.services.add_import_module import AddImportModuleTool


@contextmanager
def environment_fixture(context: AgentContext):
    environment = context["pool"].use(context, "CLEAN")
    try:
        yield environment
    finally:
        context["pool"].restore(context)


@pytest.mark.skip(reason="Skipping test .cache dir is changed")
def test_add_import_twice(detection_jvm_oripa_cpv_0: tuple[Path, Path]):
    context, _detection = AIxCCContextBuilder(
        *detection_jvm_oripa_cpv_0,
        evaluator=MockEvaluator(),
    ).build(previous_action=HeadAction())

    with environment_fixture(context) as environment:
        file_path = Path(
            context["pool"].source_directory
            / "src/main/java/oripa/persistence/doc/loader/LoaderXML.java"
        )

        module_name = "org.w3c.dom.Document"
        AddImportModuleTool(context, environment)._run(  # type: ignore
            module_name, str(file_path)
        )

        module_name = "javax.xml.parsers.DocumentBuilder"
        AddImportModuleTool(context, environment)._run(  # type: ignore
            module_name, str(file_path)
        )

        content = file_path.read_text()
        assert "import org.w3c.dom.Document;" in content
        assert "import javax.xml.parsers.DocumentBuilder;" in content
