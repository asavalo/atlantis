from packages.crete.framework.language_parser.services.tree_sitter import (
    PreprocessorAnalyzer,
)


def test_preprocessor_analyzer():
    code = [
        "#ifdef LEVEL1",
        "  int level1_var = 100;",
        "  #ifndef LEVEL2_DISABLED",
        "    int level2_var = 200;",
        "    #ifdef LEVEL3",
        "      int level3_var = 300;",
        "    #endif",
        "    int after_level3 = 301;",
        "  #endif",
        "  int after_level2 = 201;",
        "#endif",
        "#if defined(OPTION_A)",
        "  int option_a = 10;",
        "#elif defined(OPTION_B)",
        "  int option_b = 20;",
        "#else",
        "  int fallback = 30;",
        "#endif",
        "int global_var = 101;",
    ]

    analyzer = PreprocessorAnalyzer(code)

    assert len(analyzer.get_stack_at_line(0)) == 1
    assert len(analyzer.get_stack_at_line(1)) == 1
    assert len(analyzer.get_stack_at_line(2)) == 2
    assert analyzer.get_stack_at_line(2)[1][0] == "#ifndef"
    assert len(analyzer.get_stack_at_line(3)) == 2
    assert len(analyzer.get_stack_at_line(4)) == 3
    assert len(analyzer.get_stack_at_line(5)) == 3
    assert len(analyzer.get_stack_at_line(6)) == 2
    assert len(analyzer.get_stack_at_line(7)) == 2
    assert len(analyzer.get_stack_at_line(8)) == 1
    assert len(analyzer.get_stack_at_line(9)) == 1
    assert len(analyzer.get_stack_at_line(10)) == 0

    assert len(analyzer.get_stack_at_line(11)) == 1
    assert analyzer.get_stack_at_line(11)[0][0] == "#if"
    assert len(analyzer.get_stack_at_line(13)) == 1
    assert analyzer.get_stack_at_line(13)[0][0] == "#if"
    assert len(analyzer.get_stack_at_line(15)) == 1
    assert analyzer.get_stack_at_line(15)[0][0] == "#if"
    assert len(analyzer.get_stack_at_line(17)) == 0

    level3_stack = analyzer.get_stack_at_line(5)
    assert level3_stack[0][1] == 0
    assert level3_stack[1][1] == 2
    assert level3_stack[2][1] == 4

    assert analyzer.get_earliest_directive_line(2, 5) == 0
    assert analyzer.get_earliest_directive_line(18, 18) is None

    print("All tests passed!")
