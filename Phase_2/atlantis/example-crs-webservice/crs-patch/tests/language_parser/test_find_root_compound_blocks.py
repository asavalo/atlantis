import inspect
from typing import List, Dict, Any
from packages.crete.framework.language_parser.services.tree_sitter import (
    find_root_compound_blocks,
)


TEST_CASES: List[Dict[str, Any]] = [
    {
        "test_name": "Common Closing Brace",
        "code": inspect.cleandoc("""
            void xyz(){
            #ifdef FEATURE_A
                void abc() {
            #else
                void abc_d() {
            #endif
                int x = 10;
            #ifdef FEATURE_A
                }
            #else
                    i = 1;
                }
            #endif
            }
        """),
        "correct_brace_pairs": [(0, 13)],
        "c_functions": ["xyz"],
    },
    {
        "test_name": "Cross Preprocessor Braces",
        "code": inspect.cleandoc("""
            #ifdef FEATURE_A
                void abc() {
            #else
                void abc_d() {
            #endif
                    int x = 10;
            #ifdef FEATURE_A
                }
            #else
                    i = 1;
                }
            #endif
        """),
        "correct_brace_pairs": [(1, 7)],
        "c_functions": ["abc"],
    },
    {
        "test_name": "Nested Preprocessor Directives",
        "code": inspect.cleandoc("""
            #ifdef OUTER
                #ifdef INNER
                    void inner_func() {
                        return;
                    }
                #else
                    void alt_inner_func() {
                        return;
                    }
                #endif
            #else
                void outer_func() {
                    return;
                }
            #endif
        """),
        "correct_brace_pairs": [(2, 4)],
        "c_functions": ["inner_func"],
    },
    {
        "test_name": "Interleaved Preprocessor Directives",
        "code": inspect.cleandoc("""
            #ifdef CONFIG_A
                void func_a() {
            #endif
                    int common_code = 1;
            #ifdef CONFIG_A
                }
            #endif
            
            #ifndef CONFIG_A
                void func_b() {
                    int b_only = 2;
                }
            #endif
        """),
        "correct_brace_pairs": [(1, 5), (9, 11)],
        "c_functions": ["func_a", "func_b"],
    },
    {
        "test_name": "Complex if-elif-else Preprocessor",
        "code": inspect.cleandoc("""
            #if defined(PLATFORM_A)
                int platform_a_func() {
                    return 1;
                }
            #elif defined(PLATFORM_B)
                int platform_b_func() {
                    return 2;
                }
            #elif defined(PLATFORM_C)
                int platform_c_func() {
                    return 3;
                }
            #else
                int default_platform_func() {
                    return 0;
                }
            #endif
        """),
        "correct_brace_pairs": [(1, 3)],
        "c_functions": ["platform_a_func"],
    },
    {
        "test_name": "Non-terminated Preprocessor Block",
        "code": inspect.cleandoc("""
            void normal_func() {
                int x = 1;
            }
            
            #ifdef EXPERIMENTAL
            void experimental_func() {
                // This block is not closed with #endif
                int y = 2;
            }
        """),
        "correct_brace_pairs": [(0, 2), (5, 8)],
        "c_functions": ["normal_func", "experimental_func"],
    },
    {
        "test_name": "Function with Linebreak",
        "code": inspect.cleandoc("""
            int multiply(int a, int b)
            {
                return a * b;
            }
        """),
        "correct_brace_pairs": [(1, 3)],
        "c_functions": ["multiply"],
    },
    {
        "test_name": "Multiple Functions",
        "code": inspect.cleandoc("""
            int add(int a, int b) {
                return a + b;
            }
            
            int subtract(int a, int b) {
                return a - b;
            }
        """),
        "correct_brace_pairs": [(0, 2), (4, 6)],
        "c_functions": ["add", "subtract"],
    },
    {
        "test_name": "Nested Braces",
        "code": inspect.cleandoc("""
            int complex_function(int a, int b) {
                if (a > b) {
                    return a - b;
                } else {
                    return b - a;
                }
            }
        """),
        "correct_brace_pairs": [(0, 6)],
        "c_functions": ["complex_function"],
    },
    {
        "test_name": "Function with Comments",
        "code": inspect.cleandoc("""
            /* This is a function with comments */
            int add(int a, int b) {
                // Add two numbers
                return a + b; /* Return result */
            }
        """),
        "correct_brace_pairs": [(1, 4)],
        "c_functions": ["add"],
    },
    {
        "test_name": "Function with String Literals",
        "code": inspect.cleandoc("""
            void print_message() {
                printf("This is a { in a string");
                printf("This is a } in a string");
                char c = '{';  // Character literal
            }
        """),
        "correct_brace_pairs": [(0, 4)],
        "c_functions": ["print_message"],
    },
    {
        "test_name": "Preprocessor Directives with Non-matching Braces",
        "code": inspect.cleandoc("""
            #ifdef DEBUG
            void debug_function() {
                printf("Debug mode");
            #else
            void release_function() {
                // Empty function
            #endif
                return;
            }
        """),
        "correct_brace_pairs": [(1, 8)],
        "c_functions": ["debug_function"],
    },
    {
        "test_name": "Mix of Preprocessor and Normal Code",
        "code": inspect.cleandoc("""
            void common_function() {
                int x = 0;
            #ifdef FEATURE
                x = get_feature_value();
            #endif
                process(x);
            }
        """),
        "correct_brace_pairs": [(0, 6)],
        "c_functions": ["common_function"],
    },
]


def test_find_root_compound_blocks():
    failures = 0

    for i, test_case in enumerate(TEST_CASES):
        print(f"\nRunning test: {test_case['test_name']} ({i + 1}/{len(TEST_CASES)})")

        code_lines = test_case["code"].split("\n")
        result = find_root_compound_blocks(code_lines)

        expected = test_case["correct_brace_pairs"]
        if result == expected:
            print(f"Pass: Found {len(result)} brace pairs correctly")
            print(f"    Functions identified: {', '.join(test_case['c_functions'])}")
        else:
            failures += 1
            print("Fail: Brace pairs don't match")
            print(f"    Expected: {expected}")
            print(f"    Actual: {result}")

            missing = [pair for pair in expected if pair not in result]
            extra = [pair for pair in result if pair not in expected]

            if missing:
                print(f"    Missing pairs: {missing}")
            if extra:
                print(f"    Extra pairs: {extra}")

    total = len(TEST_CASES)
    passed = total - failures
    print("\n===== Test Summary =====")
    print(f"Passed: {passed}/{total} ({passed / total * 100:.1f}%)")

    assert failures == 0
