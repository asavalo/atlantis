from pathlib import Path

from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.mock import MockEvaluator
from crete.framework.tools.services import SearchSymbolTool

MOCK_JAVA_EXECUTE_COMMAND_DEFINITION = """    12: public static void executeCommand(String data) {
    13:         //Only "ls", "pwd", and "echo" commands are allowed.
    14:         try{
    15:             ProcessBuilder processBuilder = new ProcessBuilder();
    16:             processBuilder.command(data);
    17:             Process process = processBuilder.start();
    18:             process.waitFor();
    19:         } catch (Exception e) {
    20:             e.printStackTrace();
    21:         }
    22:     }"""


def test_search_symbol_with_line_number(
    detection_jvm_mock_java_cpv_0: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_jvm_mock_java_cpv_0,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    symbol_name = "executeCommand"
    ret = SearchSymbolTool(
        context, context["pool"].source_directory, with_line_number=True
    )._run(symbol_name)  # type: ignore

    context["logger"].info(ret)
    assert ret == MOCK_JAVA_EXECUTE_COMMAND_DEFINITION


def test_search_symbol_found_in_other_direcotry(
    detection_jvm_mock_java_cpv_0: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_jvm_mock_java_cpv_0,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    source_directory = context["pool"].source_directory

    symbol_name = "executeCommand"
    ret = SearchSymbolTool(context, source_directory, with_line_number=True)._run(  # type: ignore
        symbol_name, str(source_directory / "src" / "test")
    )

    context["logger"].info(ret)
    assert (
        ret
        == MOCK_JAVA_EXECUTE_COMMAND_DEFINITION
        + "\n\n"
        + "The symbol definition is located in other file: "
        + "src/main/java/com/aixcc/mock_java/App.java"
    )
