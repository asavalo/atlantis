import inspect
from pathlib import Path
from typing import Dict, List, Optional, Union

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.language_parser.functions import get_declaration_by_name

# Define expected function signatures and characteristics
EXPECTED_FUNCTION_DATA: Dict[str, Dict[str, Union[str, int, Optional[str]]]] = {
    "ngx_log_init": {
        "file_path": "src/core/ngx_log.c",
        "start_line": 317,
        "end_line": 398,
        "code_preview": inspect.cleandoc("""
            ngx_log_init(u_char *prefix, u_char *error_log)
            {
                u_char  *p, *name;
                size_t   nlen, plen;
                
                ngx_log.file = &ngx_log_file;
                ngx_log.log_level = NGX_LOG_NOTICE;
            """),
    },
    "ngx_resolver_process_a": {
        "file_path": "src/core/ngx_resolver.c",
        "start_line": 1932,
        "end_line": 2584,
        "code_preview": inspect.cleandoc("""
            ngx_resolver_process_a(ngx_resolver_t *r, u_char *buf, size_t n,
                ngx_uint_t ident, ngx_uint_t code, ngx_uint_t qtype,
                ngx_uint_t nan, ngx_uint_t trunc, ngx_uint_t ans)
            {
                char                       *err;
                u_char                     *cname;
                size_t                      len;
            """),
    },
    "ngx_slprintf": {
        "file_path": "src/core/ngx_string.c",
        "start_line": 150,
        "end_line": 161,
        "code_preview": inspect.cleandoc("""
            ngx_slprintf(u_char *buf, u_char *last, const char *fmt, ...)
            {
                u_char   *p;
                va_list   args;
                
                va_start(args, fmt);
                p = ngx_vslprintf(buf, last, fmt, args);
            """),
    },
    "ngx_snprintf": {
        "file_path": "src/core/ngx_string.c",
        "start_line": 136,
        "end_line": 147,
        "code_preview": inspect.cleandoc("""
            ngx_snprintf(u_char *buf, size_t max, const char *fmt, ...)
            {
                u_char   *p;
                va_list   args;
                
                va_start(args, fmt);
                p = ngx_vslprintf(buf, buf + max, fmt, args);
            """),
    },
    "ngx_ssl_parse_time": {
        "file_path": "src/event/ngx_event_openssl.c",
        "start_line": 5905,
        "end_line": 5941,
        "code_preview": inspect.cleandoc("""
            ngx_ssl_parse_time(
            #if OPENSSL_VERSION_NUMBER > 0x10100000L
                const
            #endif
                ASN1_TIME *asn1time, ngx_log_t *log)
            {
                BIO     *bio;
            """),
    },
    "ngx_vslprintf": {
        "file_path": "src/core/ngx_string.c",
        "start_line": 164,
        "end_line": 481,
        "code_preview": inspect.cleandoc("""
            ngx_vslprintf(u_char *buf, u_char *last, const char *fmt, va_list args)
            {
                u_char                *p, zero;
                int                    d;
                double                 f;
                size_t                 slen;
                int64_t                i64;
            """),
    },
}


@pytest.mark.slow
def test_get_declaration_by_name(detection_nginx_cpv_10: tuple[Path, Path]):
    target_functions = list(EXPECTED_FUNCTION_DATA.keys())

    context, _ = AIxCCContextBuilder(
        *detection_nginx_cpv_10, evaluator=DummyEvaluator()
    ).build(previous_action=HeadAction())

    failed_tests: Dict[str, List[str]] = {}

    for target_name in target_functions:
        expected = EXPECTED_FUNCTION_DATA[target_name]
        file_path = expected["file_path"]
        assert isinstance(file_path, str)

        abs_src_path = context["pool"].source_directory / file_path

        result = get_declaration_by_name(
            context["language_parser"], context, abs_src_path, target_name
        )

        if result is None:
            failed_tests[target_name] = ["Function declaration not found"]
            continue

        declaration_name, declaration_node = result
        errors: List[str] = []

        if declaration_name != target_name:
            errors.append(
                f"Expected function name '{target_name}', got '{declaration_name}'"
            )

        if file_path not in str(declaration_node.file):
            errors.append(
                f"Expected file path containing '{file_path}', got '{declaration_node.file}'"
            )

        expected_start_line = expected.get("start_line")
        if (
            isinstance(expected_start_line, int)
            and declaration_node.start_line != expected_start_line
        ):
            errors.append(
                f"Expected start_line {expected_start_line}, got {declaration_node.start_line}"
            )

        expected_end_line = expected.get("end_line")
        if (
            isinstance(expected_end_line, int)
            and declaration_node.end_line != expected_end_line
        ):
            errors.append(
                f"Expected end_line {expected_end_line}, got {declaration_node.end_line}"
            )

        expected_code_preview = expected.get("code_preview")
        if isinstance(expected_code_preview, str) and expected_code_preview:
            actual_lines = declaration_node.text.split("\n")
            preview_lines = expected_code_preview.strip().split("\n")

            if len(actual_lines) < len(preview_lines):
                errors.append(
                    f"Function text has fewer lines than expected: got {len(actual_lines)}, expected at least {len(preview_lines)}"
                )
            else:
                for i, expected_line in enumerate(preview_lines):
                    if i < len(actual_lines):
                        actual_line = actual_lines[i].rstrip()
                        expected_line = expected_line.rstrip()
                        if expected_line != actual_line:
                            errors.append(
                                f"Line {i + 1} mismatch:\nExpected: '{expected_line}'\nActual: '{actual_line}'"
                            )

        if errors:
            failed_tests[target_name] = errors

    error_message = ""
    if failed_tests:
        for func_name, errors in failed_tests.items():
            error_message += f"\n{func_name} failed validation:\n"
            for error in errors:
                error_message += f"  - {error}\n"

    assert not failed_tests, f"Function validation failed:{error_message}"
