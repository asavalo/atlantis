import inspect
from typing import List, Dict, Any, Tuple
from packages.crete.framework.language_parser.services.tree_sitter import (
    mapping_brace_to_function,
    find_root_compound_blocks,
)

TEST_CASES: List[Dict[str, Any]] = [
    {
        "test_name": "Complex Preprocessor with Comments and Function Definition",
        "code": inspect.cleandoc("""
            /* 
             * Multiple header comments
             * spanning several lines
             */
            
            #ifndef _INCLUDED_HEADER_H
            #define _INCLUDED_HEADER_H
            
            // Forward declarations
            struct ComplexStruct; // (
            
            #ifdef DEBUG_MODE
                /* Debug version of the function with extra logging */
                #define LOG_FUNC(x) printf("Debug: %s\\n", x)
                
                /**
                 * Documentation comment
                 * for the complex function
                 */
                #if defined(PLATFORM_LINUX)
                    // Linux specific implementation
                    static time_t
                    int complex_function(
                        #if OPENSSL_VERSION_NUMBER > 0x10100000L
                            const
                        #endif
                        int param1,   // First parameter
                        int param2)   /* Second parameter */
                    {
                        /* Function body */
                        LOG_FUNC("complex_function");
                        return param1 + param2;
                    }
                #elif defined(PLATFORM_WINDOWS)
                    // Windows specific implementation
                    int complex_function(
                        int param1,
                        int param2) 
                    {
                        return param1 * param2;
                    }
                #else
                    // Default implementation
                    int complex_function(int param1, int param2) {
                        return param1 - param2;
                    }
                #endif
            #else
                /* Release version without logging */
                #define LOG_FUNC(x)
                
                // Simple inline function for release mode
                static inline int complex_function(int a, int b) {
                    return a + b;
                }
            #endif
            
            #endif /* _INCLUDED_HEADER_H */
        """),
        "brace_line": 28,
        "expected_function_name": "complex_function",
    },
    {
        "test_name": "Nested Function with Mixed Preprocessor and Comments",
        "code": inspect.cleandoc("""
            /*******************************************
             * This file contains nested functions and 
             * preprocessor directives for testing.
             *******************************************/
             
            // Global declarations
            int global_var = 0;
            
            #if defined(EXTENDED_API)
                /* 
                 * Extended API functions are only available
                 * in the premium version
                 */
                
                // Helper function prototype
                void helper_func();
                
                #ifdef _MSC_VER
                    /* Microsoft compiler specific */
                    #pragma warning(disable: 4996)
                    
                    /* Previous function prototypes */
                    int previous_func1();
                    int previous_func2();
                #endif
                
                /* 
                 * Main outer function containing
                 * nested inner functions
                 */
                int outer_function(
                    void* context,      // Context pointer (
                    unsigned long flags // Option flags
                ) #ifndef NO_NOEXCEPT
                    noexcept            // Exception specification
                  #endif
                {
                    #ifdef ENABLE_LOGGING
                        // Log function entry
                        log_entry("outer_function");
                    #endif
                    
                    /* Local variables */
                    int result = 0;
                    
                    #ifdef ENABLE_NESTED_FUNCTIONS
                        /* GCC nested function */
                        int inner_function(int x) {
                            return x * 2;
                        }
                        
                        result = inner_function(5);
                    #else
                        result = 10;
                    #endif
                    
                    return result;
                }
            #else
                /* Basic API only includes simplified functions */
                int outer_function() {
                    return 42;
                }
            #endif
        """),
        "brace_line": 36,
        "expected_function_name": "outer_function",
    },
]


def test_mapping_brace_to_function():
    failures = 0

    for i, test_case in enumerate(TEST_CASES):
        print(f"\nRunning test: {test_case['test_name']} ({i + 1}/{len(TEST_CASES)})")

        code_lines = test_case["code"].split("\n")

        brace_pairs = find_root_compound_blocks(code_lines)
        brace_line_valid = False
        closing_brace_line = None
        target_brace_pair: Tuple[int, int] = (-1, -1)

        for start_line, end_line in brace_pairs:
            if start_line == test_case["brace_line"]:
                brace_line_valid = True
                closing_brace_line = end_line
                target_brace_pair = (start_line, end_line)
                break

        if not brace_line_valid:
            print(
                f"Warning: brace_line {test_case['brace_line']} is not found in find_root_compound_blocks results"
            )
            print(f"Available brace pairs: {brace_pairs}")
            print("Code context around expected brace line:")
            start_idx = max(0, test_case["brace_line"] - 2)
            end_idx = min(len(code_lines), test_case["brace_line"] + 3)
            for j in range(start_idx, end_idx):
                prefix = "  > " if j == test_case["brace_line"] else "    "
                print(f"{prefix}Line {j}: {code_lines[j]}")
            failures += 1
            continue

        print(
            f"Confirmed: brace_line {test_case['brace_line']} is valid; closing brace at line {closing_brace_line}"
        )

        function_map = mapping_brace_to_function(code_lines, [target_brace_pair])

        if not function_map:
            failures += 1
            print("Fail: Function name not found for any brace pair")
            continue

        expected = test_case["expected_function_name"]
        function_name = None
        for _, name in function_map.items():
            if name == expected:
                function_name = name
                break

        if function_name is None:
            failures += 1
            if function_map:
                print(f"Fail: Expected function name '{expected}' not found in results")
                print(f"Available function names: {list(function_map.values())}")
                print(f"Function map: {function_map}")
            else:
                print("Fail: No function names found")
            continue

        print(f"Pass: Found correct function name: {function_name}")

    total = len(TEST_CASES)
    passed = total - failures
    print("\n===== Test Summary =====")
    print(f"Passed: {passed}/{total} ({passed / total * 100:.1f}%)")

    assert failures == 0
