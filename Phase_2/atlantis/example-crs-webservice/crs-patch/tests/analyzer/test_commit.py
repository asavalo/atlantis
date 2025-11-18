from pathlib import Path
from typing import List, Tuple

import pytest
from crete.atoms.action import HeadAction
from crete.framework.analyzer.services.commit.functions import (
    convert_all_diff_to_patches,
    extract_patches_from_relevant_call_stack,
    get_all_diff,
    get_call_stack_array,
    parse_diff_output_to_function_diffs,
    search_commit_by_patches,
)
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder


def test_parse_diff_output_to_function_diffs():
    file_path = "file1.c"

    example_diff1 = """diff --git a/file1.c b/file1.c
--- a/file1.c
+++ b/file1.c
@@ -1432,14 +1432,17 @@ void function_a(char* arg1, void* arg2, int arg3)
{
    call_some_function(arg1);

    if (arg2 != NULL)
+   {
       validate_input(arg2);
+   }
    
    if (arg3 > 0) {
        process_data(arg1, arg2, arg3);
    }
    
    return;
}

@@ -3500,9 +3500,26 @@ char* check_keyword(const char* key, char* new_key)
{
  if (key == NULL || strlen(key) == 0) {
    return NULL;
  }
  
  strncpy(new_key, key, MAX_KEY_SIZE - 1);
  new_key[MAX_KEY_SIZE - 1] = '\\0';
  
  return (new_key);
}

+void validate_string(void* context, const char* input, 
+                     unsigned int max_length)
+{
+   if (input == NULL)
+      return;
+      
+   if (strlen(input) > max_length) {
+      report_error(context, "string too long");
+   }
+   
+   for (size_t i = 0; i < strlen(input); i++) {
+       if (!isalnum(input[i]) && input[i] != '_') {
+           report_error(context, "invalid character");
+       }
+   }
+}
+
#if defined(FEATURE_A) && !defined(FEATURE_B)
/* Returns success (0) or failure (1) */"""

    diff_infos = parse_diff_output_to_function_diffs(example_diff1, file_path)

    assert diff_infos and len(diff_infos) == 2, (
        f"Expected 2 diffs, got {len(diff_infos)}"
    )

    assert diff_infos[0].file_path == file_path
    assert diff_infos[0].original_line_span == (1432, 1445)
    assert diff_infos[0].new_line_span == (1432, 1448)
    assert "function_a" in diff_infos[0].diff

    assert diff_infos[1].file_path == file_path
    assert diff_infos[1].original_line_span == (3500, 3508)
    assert diff_infos[1].new_line_span == (3500, 3525)
    assert "validate_string" in diff_infos[1].diff

    file_path2 = "file2.c"
    example_diff2 = """diff --git a/file2.c b/file2.c
--- a/file2.c
+++ b/file2.c
@@ -228,19 +228,22 @@ int function_b(struct data_t* data, int length)
{
    int result = 0;
    
    if (length <= 0 || data == NULL) {
        return -1;
    }
    
    if (data->ptr != NULL)
+    {
       free_data(data->ptr);
+    }
    
    if (data->flags & FLAG_PERSISTENT) {
       data->ptr = NULL;
       data->size = 0;
    } else {
       destroy_data_struct(data);
    }
    
    return result;
}"""

    diff_infos = parse_diff_output_to_function_diffs(example_diff2, file_path2)

    assert diff_infos and len(diff_infos) == 1, (
        f"Expected 1 diff, got {len(diff_infos)}"
    )
    assert diff_infos[0].file_path == file_path2
    assert diff_infos[0].original_line_span == (228, 246)
    assert diff_infos[0].new_line_span == (228, 249)
    assert "function_b" in diff_infos[0].diff

    file_path3 = "complex_func.c"
    example_diff3 = """diff --git a/complex_func.c b/complex_func.c
--- a/complex_func.c
+++ b/complex_func.c
@@ -370,15 +385,21 @@ void* process_complex_input(runtime_context_t* ctx, buffer_t* input_buffer, size_t max_size, int flags)
{   
    /* Process the input buffer according to flags */
    switch (flags & MASK_OPERATION) {
        case OP_PARSE:
            result = parse_buffer_content(ctx, input_buffer);
+           if (!validate_result(result)) {
+               log_error("Invalid parse result", ctx->log_level);
+           }
            break;
            
        case OP_TRANSFORM:
            result = transform_buffer(ctx, input_buffer);
            break;
    }
    
    if (!result && (flags & FLAG_FALLBACK)) {
-       return create_fallback_result(ctx);
+       result = create_fallback_result(ctx);
+       log_info("Using fallback result", ctx->log_level);
    }
    
    return result;
}"""

    diff_infos = parse_diff_output_to_function_diffs(example_diff3, file_path3)

    assert diff_infos and len(diff_infos) == 1, (
        f"Expected 1 diff, got {len(diff_infos)}"
    )
    assert diff_infos[0].file_path == file_path3
    assert diff_infos[0].original_line_span == (370, 384)
    assert diff_infos[0].new_line_span == (385, 405)
    assert "process_complex_input" in diff_infos[0].diff
    assert "log_info" in diff_infos[0].diff


@pytest.mark.slow
def test_libpng_call_stack_patches(
    detection_cpp_example_libpng_cpv_0_delta: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_cpp_example_libpng_cpv_0_delta,
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    call_stack_array = [
        ("OSS_FUZZ_png_crc_read", "pngrutil.c", 1432),
        ("OSS_FUZZ_png_handle_iCCP", "pngread.c", 229),
    ]

    patches = extract_patches_from_relevant_call_stack(
        context, detection, call_stack_array
    )

    assert patches is not None, "patches should not be None"

    assert any(patch.file_path == "pngrutil.c" for patch in patches), (
        "No patches found for pngrutil.c"
    )

    pngrutil_patches = [patch for patch in patches if patch.file_path == "pngrutil.c"]
    assert len(pngrutil_patches) > 0, "At least one patch for pngrutil.c should exist"
    assert pngrutil_patches[0].function_name == "OSS_FUZZ_png_crc_read", (
        f"Expected function name: OSS_FUZZ_png_crc_read, actual: {pngrutil_patches[0].function_name}"
    )

    call_stack_array = [
        ("OSS_FUZZ_png_handle_iCCP", "pngread.c", 229),
        ("OSS_FUZZ_png_warning", "pngerror.c", 506),
    ]

    patches = extract_patches_from_relevant_call_stack(
        context, detection, call_stack_array
    )

    assert patches is not None, "patches should not be None"
    assert len(patches) == 0, "patches should be None"

    call_stack_array: List[Tuple[str, str, int]] = []

    patches = extract_patches_from_relevant_call_stack(
        context, detection, call_stack_array
    )

    assert patches is not None, "patches should not be None"
    assert len(patches) == 0, "patches should be None"


@pytest.mark.slow
def test_llm_commit_analyze_with_empty_call_stack(
    detection_cpp_example_libpng_cpv_0_delta: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_cpp_example_libpng_cpv_0_delta,
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    call_stack_array: List[Tuple[str, str, int]] = []

    patches = extract_patches_from_relevant_call_stack(
        context, detection, call_stack_array
    )
    assert patches is not None, "patches should not be None"
    assert len(patches) == 0, "patches should be None"

    all_diff = get_all_diff(context, detection)
    assert all_diff is not None, "all_diff should not be None"


@pytest.mark.slow
def test_example_libpng(
    detection_cpp_example_libpng_cpv_0_delta: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_cpp_example_libpng_cpv_0_delta,
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    all_diff = get_all_diff(context, detection)

    assert all_diff is not None, "all_diff should not be None"

    assert len(all_diff) == 2, f"Expected 2 commits, but got {len(all_diff)}"

    call_stack_array = [
        ("OSS_FUZZ_png_calculate_crc", "pngrutil.c", 216),
        ("OSS_FUZZ_png_get_io_ptr", "contrib/oss-fuzz/libpng_read_fuzzer.cc", 70),
        ("_Z14user_read_dataP14png_struct_defPhm", "pngrio.c", 36),
        ("OSS_FUZZ_png_read_data", "pngrutil.c", 215),
        ("OSS_FUZZ_png_crc_read", "pngrutil.c", 1432),
        ("OSS_FUZZ_png_handle_iCCP", "pngread.c", 229),
        ("OSS_FUZZ_png_chunk_unknown_handling", "pngread.c", 144),
        ("OSS_FUZZ_png_warning", "pngerror.c", 506),
        ("OSS_FUZZ_png_chunk_warning", "pngerror.c", 369),
        ("OSS_FUZZ_png_benign_error", "pngrutil.c", 3244),
    ]

    function_patches = extract_patches_from_relevant_call_stack(
        context, detection, call_stack_array
    )

    assert function_patches is not None, "function_patches should not be None"


@pytest.mark.slow
def test_example_c_libcue_fuzz(
    detection_c_libcue_cpv_0_delta: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_libcue_cpv_0_delta,
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    all_diff = get_all_diff(context, detection)

    assert all_diff is not None, "all_diff should not be None"
    assert len(all_diff) == 1, f"Expected 1 commits, but got {len(all_diff)}"

    call_stack_array = get_call_stack_array(context, detection)

    assert call_stack_array is not None, "call_stack_array should not be None"

    expected_functions = [
        "track_set_index",
        "yyparse",
        "cue_parse_string",
    ]
    expected_files = ["cd.c", "cue_parser.y", "cue_parser.y"]

    func_found = False
    file_found = False
    for func_name, file_path, _ in call_stack_array:
        if any(expected_func in func_name for expected_func in expected_functions):
            func_found = True
        if any(expected_file in file_path for expected_file in expected_files):
            file_found = True

    assert func_found, "Expected functions not found in call stack"
    assert file_found, "Expected files not found in call stack"

    found_functions = [
        func
        for func, _, _ in call_stack_array
        if any(expected_func in func for expected_func in expected_functions)
    ]
    assert len(found_functions) > 0, (
        f"Expected functions not found in call stack: {call_stack_array}"
    )

    patches = extract_patches_from_relevant_call_stack(
        context, detection, call_stack_array
    )

    assert patches is not None, "patches should not be None"


@pytest.mark.skip(reason="Jenkins build failed in CI environment")
def test_jenkins_three_vulnerability(
    detection_jvm_jenkins_cpv_6_delta: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_jvm_jenkins_cpv_6_delta,
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    all_diff = get_all_diff(context, detection)
    assert all_diff is not None, "all_diff should not be None"
    assert len(all_diff) > 0, f"Expected at least 1 commit, but got {len(all_diff)}"

    call_stack_array = [
        (
            "__crash_lines__",
            "plugins/toy-plugin/src/main/java/io/jenkins/plugins/toyplugin/StateMonitor.java",
            57,
        )
    ]

    patches = extract_patches_from_relevant_call_stack(
        context, detection, call_stack_array
    )

    assert patches is not None, "patches should not be None"

    if len(patches) == 0:
        patches = convert_all_diff_to_patches(all_diff)
    else:
        expanded_patches = search_commit_by_patches(patches, all_diff)
        patches = expanded_patches


# def test_mock_c(
#     detection_c_mock_c_cpv_0_delta: tuple[Path, Path],
# ):
#     context, detection = AIxCCContextBuilder(
#         *detection_c_mock_c_cpv_0_delta,
#     ).build(
#         previous_action=HeadAction(),
#     )

#     context["pool"].restore(context)

#     call_stack_array = get_call_stack_array(context, detection)

#     assert call_stack_array is not None, "call_stack_array should not be None"

#     function_patches = get_function_patches(context, detection, call_stack_array)

#     if function_patches is None or len(function_patches) == 0:
#         all_diff = get_all_diff(context, detection)
#         if all_diff is None:
#             return None

#         function_patches = convert_all_diff_to_patches(all_diff)


# @pytest.mark.skip(reason="Jenkins build failed in CI environment")
# def test_custom_jvm_imaging(
#     detection_jvm_imaging_cpv_2_delta: tuple[Path, Path],
# ):
#     context, detection = AIxCCContextBuilder(
#         *detection_jvm_imaging_cpv_2_delta,
#     ).build(
#         previous_action=HeadAction(),
#     )

#     context["pool"].restore(context)

#     call_stack_array = get_call_stack_array(context, detection)

#     assert call_stack_array is not None, "call_stack_array should not be None"

#     function_patches = get_function_patches(context, detection, call_stack_array)

#     if function_patches is None or len(function_patches) == 0:
#         all_diff = get_all_diff(context, detection)
#         if all_diff is None:
#             return None

#         function_patches = convert_all_diff_to_patches(all_diff)
