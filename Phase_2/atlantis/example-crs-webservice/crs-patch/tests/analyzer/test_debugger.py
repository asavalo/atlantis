from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.analyzer.services.debugger import DebuggerAnalyzer
from crete.framework.analyzer.services.debugger.functions import dump_runtime_values
from crete.framework.analyzer.services.debugger.models import Breakpoint
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.insighter.services.stacktrace import RuntimeValue
from python_oss_fuzz.debugger.jdb import run_jdb_commands


@pytest.mark.skip(reason="Needs to update for new mock-c")
def test_mock_c_cpv_0(detection_c_mock_c_cpv_0: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_c_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    debugger_analyzer = DebuggerAnalyzer()
    breakpoints = [
        Breakpoint(
            location="process_input_header",
            expressions=["p buf", "ptype buf"],
        ),
    ]

    breakpoint_outs = debugger_analyzer.analyze(context, detection, breakpoints)
    assert breakpoint_outs is not None
    assert r"$1 = '\000' <repeats 63 times>" in breakpoint_outs
    assert "type = char [64]" in breakpoint_outs


@pytest.mark.slow
def test_babynginx_cpv_0(
    detection_c_babynginx_cpv_0: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_babynginx_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    debugger_analyzer = DebuggerAnalyzer()
    breakpoints = [
        Breakpoint(
            location="ngx_http_process_custom_features",
            expressions=[
                "ptype r",
                "ptype h",
                "ptype offset",
                "ptype features",
                "ptype custom_flag_value",
            ],
        ),
    ]

    breakpoint_outs = debugger_analyzer.analyze(context, detection, breakpoints)
    assert breakpoint_outs is not None
    assert (
        """type = struct ngx_http_request_s {
    uint32_t signature;
    ngx_connection_t *connection;
    void **ctx;
    void **main_conf;
    void **srv_conf;
    void **loc_conf;
    ngx_http_event_handler_pt read_event_handler;
    ngx_http_event_handler_pt write_event_handler;
    ngx_http_cache_t *cache;
    ngx_http_upstream_t *upstream;
    ngx_array_t *upstream_states;
    ngx_pool_t *pool;
    ngx_buf_t *header_in;
    ngx_http_headers_in_t headers_in;
    ngx_http_headers_out_t headers_out;
    ngx_http_request_body_t *request_body;
    time_t lingering_time;
    time_t start_sec;
    ngx_msec_t start_msec;
    ngx_uint_t method;
    ngx_uint_t http_version;
    ngx_str_t request_line;
    ngx_str_t uri;
    ngx_str_t args;
    ngx_str_t exten;
    ngx_str_t unparsed_uri;
    ngx_str_t method_name;
    ngx_str_t http_protocol;
    ngx_str_t schema;
    ngx_chain_t *out;
    ngx_http_request_t *main;
    ngx_http_request_t *parent;
    ngx_http_postponed_request_t *postponed;
    ngx_http_post_subrequest_t *post_subrequest;
    ngx_http_posted_request_t *posted_requests;
    ngx_int_t phase_handler;
    ngx_http_handler_pt content_handler;
    ngx_uint_t access_code;
    ngx_http_variable_value_t *variables;
    ngx_uint_t ncaptures;
    int *captures;
    u_char *captures_data;
    size_t limit_rate;
    size_t limit_rate_after;
    size_t header_size;
    off_t request_length;
    ngx_uint_t err_status;
    ngx_http_connection_t *http_connection;
    ngx_http_v2_stream_t *stream;
    ngx_http_v3_parse_t *v3_parse;
    ngx_http_log_handler_pt log_handler;
    ngx_http_cleanup_t *cleanup;
    unsigned int count : 16;
    unsigned int subrequests : 8;
    unsigned int blocked : 8;
    unsigned int aio : 1;
    unsigned int http_state : 4;
    unsigned int complex_uri : 1;
    unsigned int quoted_uri : 1;
    unsigned int plus_in_uri : 1;
    unsigned int empty_path_in_uri : 1;
    unsigned int invalid_header : 1;
    unsigned int add_uri_to_alias : 1;
    unsigned int valid_location : 1;
    unsigned int valid_unparsed_uri : 1;
    unsigned int uri_changed : 1;
    unsigned int uri_changes : 4;
    unsigned int request_body_in_single_buf : 1;
    unsigned int request_body_in_file_only : 1;
    unsigned int request_body_in_persistent_file : 1;
    unsigned int request_body_in_clean_file : 1;
    unsigned int request_body_file_group_access : 1;
    unsigned int request_body_file_log_level : 3;
    unsigned int request_body_no_buffering : 1;
    unsigned int subrequest_in_memory : 1;
    unsigned int waited : 1;
    unsigned int cached : 1;
    unsigned int gzip_tested : 1;
    unsigned int gzip_ok : 1;
    unsigned int gzip_vary : 1;
    unsigned int realloc_captures : 1;
    unsigned int proxy : 1;
    unsigned int bypass_cache : 1;
    unsigned int no_cache : 1;
    unsigned int limit_conn_status : 2;
    unsigned int limit_req_status : 3;
    unsigned int limit_rate_set : 1;
    unsigned int limit_rate_after_set : 1;
    unsigned int pipeline : 1;
    unsigned int chunked : 1;
    unsigned int header_only : 1;
    unsigned int expect_trailers : 1;
    unsigned int keepalive : 1;
    unsigned int lingering_close : 1;
    unsigned int discard_body : 1;
    unsigned int reading_body : 1;
    unsigned int internal : 1;
    unsigned int error_page : 1;
    unsigned int filter_finalize : 1;
    unsigned int post_action : 1;
    unsigned int request_complete : 1;
    unsigned int request_output : 1;
    unsigned int header_sent : 1;
    unsigned int response_sent : 1;
    unsigned int expect_tested : 1;
    unsigned int root_tested : 1;
    unsigned int done : 1;
    unsigned int logged : 1;
    unsigned int terminated : 1;
    unsigned int buffered : 4;
    unsigned int main_filter_need_in_memory : 1;
    unsigned int filter_need_in_memory : 1;
    unsigned int filter_need_temporary : 1;
    unsigned int preserve_body : 1;
    unsigned int allow_ranges : 1;
    unsigned int subrequest_ranges : 1;
    unsigned int single_range : 1;
    unsigned int disable_not_modified : 1;
    unsigned int stat_reading : 1;
    unsigned int stat_writing : 1;
    unsigned int stat_processing : 1;
    unsigned int background : 1;
    unsigned int health_check : 1;
    ngx_uint_t state;
    ngx_uint_t header_hash;
    ngx_uint_t lowcase_index;
    u_char lowcase_header[32];
    u_char *header_name_start;
    u_char *header_name_end;
    u_char *header_start;
    u_char *header_end;
    u_char *uri_start;
    u_char *uri_end;
    u_char *uri_ext;
    u_char *args_start;
    u_char *request_start;
    u_char *request_end;
    u_char *method_end;
    u_char *schema_start;
    u_char *schema_end;
    u_char *host_start;
    u_char *host_end;
    unsigned int http_minor : 16;
    unsigned int http_major : 16;
} *"""
        in breakpoint_outs
    ), "'ptype r' not found in breakpoint_outs"
    assert (
        """type = struct ngx_table_elt_s {
    ngx_uint_t hash;
    ngx_str_t key;
    ngx_str_t value;
    u_char *lowcase_key;
    ngx_table_elt_t *next;
} *"""
        in breakpoint_outs
    ), "'ptype h' not found in breakpoint_outs"
    assert "type = unsigned long" in breakpoint_outs, (
        "'ptype offset' not found in breakpoint_outs"
    )
    assert (
        """type = struct {
    unsigned long bitmap[1];
} *"""
        in breakpoint_outs
    ), "'ptype features' not found in breakpoint_outs"
    assert "type = int" in breakpoint_outs, (
        "'ptype custom_flag_value' not found in breakpoint_outs"
    )


def test_gdb_script_with_python(detection_c_mock_c_cpv_0: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_c_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    debugger_analyzer = DebuggerAnalyzer()

    out = debugger_analyzer.analyze(
        context, detection, [], additional_gdb_script="python print('Hello, World!')"
    )

    assert out is not None, "GDB output is None"
    assert "Hello, World!" in out, "GDB output is not correct"


def test_asan_debug(detection_c_mock_c_cpv_0: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_c_cpv_0,
    ).build(
        previous_action=HeadAction(),
    )

    runtime_values = dump_runtime_values(context, detection, depth=1)

    assert runtime_values == [
        {
            "size": RuntimeValue(value="256", type="unsigned long"),
            "buf": RuntimeValue(value="'\\000' <repeats 63 times>", type="char [64]"),
            "data": RuntimeValue(
                value="(const uint8_t *) 0x511000000180 'A' <repeats 200 times>...",
                type="const unsigned char *",
            ),
            "memcpy": RuntimeValue(
                value="{<text variable, no debug info>} 0x5555556b7c1e <memcpy>",
                type="<unknown return type> ()",
            ),
        }
    ]


@pytest.mark.flaky(reruns=3)
def test_jdb_mock_java(detection_jvm_mock_java_cpv_0: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(*detection_jvm_mock_java_cpv_0).build(
        previous_action=HeadAction(),
    )
    context["pool"].use(context, "DEBUG")

    project_name = "aixcc/jvm/mock-java"
    harness_name = "OssFuzz1"
    blob = detection.blobs[0].blob
    commands = [
        "stop at com.aixcc.mock_java.App.executeCommand",
        "cont",
        "locals",
        "cont",
        "locals",
        "cont",
    ]

    assert run_jdb_commands(project_name, harness_name, blob, commands) == [
        "stop at com.aixcc.mock_java.App.executeCommand\r\nDeferring breakpoint com.aixcc.mock_java.App.executeCommand.\r\nIt will be set after the class is loaded.\r\n",
        'cont\r\n> Set deferred breakpoint com.aixcc.mock_java.App.executeCommand\r\n\r\nBreakpoint hit: "thread=main", com.aixcc.mock_java.App.executeCommand(), line=15 bci=0\r\n\r\n',
        'locals\r\nMethod arguments:\r\ndata = "jazze"\r\nLocal variables:\r\n',
        'cont\r\n> \r\nBreakpoint hit: "thread=main", com.aixcc.mock_java.App.executeCommand(), line=15 bci=0\r\n\r\n',
        'locals\r\nMethod arguments:\r\ndata = "jazze"\r\nLocal variables:\r\n',
        "cont\r\n> \r\nThe application exited\r\n",
    ]
