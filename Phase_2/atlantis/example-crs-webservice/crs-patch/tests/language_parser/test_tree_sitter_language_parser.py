from pathlib import Path

from crete.commons.logging.hooks import use_logger
from crete.framework.language_parser.contexts import LanguageParserContext
from crete.framework.language_parser.functions import get_declaration_by_line
from crete.framework.language_parser.models import Kind, LanguageNode
from crete.framework.language_parser.services.tree_sitter import (
    TreeSitterLanguageParser,
)


def mock_language_parser_context() -> LanguageParserContext:
    return LanguageParserContext(
        {"logger": use_logger(), "logging_prefix": str(Path(__file__).stem)}
    )


def test_declaration_mock_cp_cpv_0(
    detection_c_mock_cp_cpv_0: tuple[Path, Path],
):
    src_file = detection_c_mock_cp_cpv_0[0] / "mock_vp.c"
    parser = TreeSitterLanguageParser(language="c")

    assert get_declaration_by_line(
        parser, mock_language_parser_context(), src_file, 13
    ) == (
        "func_a",
        LanguageNode(
            kind=Kind.FUNCTION,
            file=src_file,
            start_line=6,
            start_column=0,
            end_line=18,
            end_column=1,
            text=r"""void func_a(){
    char* buff;
    int i = 0;
    do{
        printf("input item:");
        buff = &items[i][0];
        i++;
        fgets(buff, 40, stdin);
        buff[strcspn(buff, "\n")] = 0;
    }while(strlen(buff)!=0);
    i--;
}""",
        ),
    )


def test_declaration_mock_cp_cpv_1(
    detection_c_mock_cp_cpv_1: tuple[Path, Path],
):
    src_file = detection_c_mock_cp_cpv_1[0] / "mock_vp.c"
    parser = TreeSitterLanguageParser(language="c")

    assert get_declaration_by_line(
        parser, mock_language_parser_context(), src_file, 27
    ) == (
        "func_b",
        LanguageNode(
            kind=Kind.FUNCTION,
            file=src_file,
            start_line=19,
            start_column=0,
            end_line=28,
            end_column=1,
            text=r"""void func_b(){
    char *buff;
    printf("done adding items\n");
    int j;
    printf("display item #:");
    scanf("%d", &j);
    buff = &items[j][0];
    printf("item %d: %s\n", j, buff);
}""",
        ),
    )


def test_blocks_mock_cp_cpv_0(
    detection_c_mock_cp_cpv_0: tuple[Path, Path],
):
    src_file = detection_c_mock_cp_cpv_0[0] / "mock_vp.c"
    parser = TreeSitterLanguageParser(language="c")

    blocks = parser.get_blocks_in_file(mock_language_parser_context(), src_file)
    assert len(blocks) == 4
    assert blocks[0] == LanguageNode(
        kind=Kind.BLOCK,
        start_line=6,
        start_column=13,
        end_line=18,
        end_column=1,
        file=src_file,
        text=r"""{
    char* buff;
    int i = 0;
    do{
        printf("input item:");
        buff = &items[i][0];
        i++;
        fgets(buff, 40, stdin);
        buff[strcspn(buff, "\n")] = 0;
    }while(strlen(buff)!=0);
    i--;
}""",
    )
