import json
import tempfile
from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.agent.services.vincent.code_inspector import VincentCodeInspector
from crete.framework.agent.services.vincent.functions import extract_requests_in_chat
from crete.framework.agent.services.vincent.nodes.requests.handlers.definition_handler import (
    DefinitionRequestHandler,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.java_definition_handler import (
    JavaDefinitionRequestHandler,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.file_handler import (
    FileRequestHandler,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.import_handler import (
    ImportRequestHandler,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.reference_handler import (
    ReferenceRequestHandler,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.similar_code_handler import (
    SimilarCodeRequestHandler,
    SnippetEmbedCache,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.line_handler import (
    LineRequestHandler,
)
from crete.framework.agent.services.vincent.nodes.requests.models import (
    LLMRequest,
    LLMRequestType,
)
from crete.framework.agent.services.vincent.nodes.requests.request_handler import (
    RequestHandler,
)
from crete.framework.agent.services.vincent.states.patch_state import (
    PatchStage,
    PatchState,
)
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from python_llm.api.actors import LlmApiManager

TEST_SNIPPET_DIRECTORY = Path(__file__).parent / "test_embeddings"
TEST_SOURCE_DIRECTORY = Path(__file__).parent / "test_source"


def test_definition_extract_requests_in_chat():
    request_text = """[REQUEST:definition]
I need to see the definition of ngx_http_userid_set_uid function (name:`ngx_http_userid_set_uid`)
[/REQUEST:definition]
"""
    requests = extract_requests_in_chat(request_text)
    assert len(requests) == 1

    request = requests[0]

    assert request.type == LLMRequestType.DEFINITION
    assert request.targets == ["ngx_http_userid_set_uid"]
    assert (
        request.raw
        == "I need to see the definition of ngx_http_userid_set_uid function (name:`ngx_http_userid_set_uid`)"
    )


def test_references_extract_requests_in_chat():
    request_text = """[REQUEST:reference]
I need to see all references to `ctx->cookie` to ensure we catch all access points (name:`ctx->cookie`)
[/REQUEST:reference]
"""
    requests = extract_requests_in_chat(request_text)
    assert len(requests) == 1

    request = requests[0]

    assert request.type == LLMRequestType.REFERENCE
    assert request.targets == ["ctx->cookie"]
    assert (
        request.raw
        == "I need to see all references to `ctx->cookie` to ensure we catch all access points (name:`ctx->cookie`)"
    )


def test_file_extract_requests_in_chat():
    request_text = """[REQUEST:file]
I need to inspect the entire userid filter module to understand the context (file:`src/http/modules/ngx_http_userid_filter_module.c`)
[/REQUEST:file]
"""
    requests = extract_requests_in_chat(request_text)
    assert len(requests) == 1

    request = requests[0]

    assert request.type == LLMRequestType.FILE
    assert request.targets == ["src/http/modules/ngx_http_userid_filter_module.c"]
    assert (
        request.raw
        == "I need to inspect the entire userid filter module to understand the context (file:`src/http/modules/ngx_http_userid_filter_module.c`)"
    )


def test_value_extract_requests_in_chat():
    request_text = """[REQUEST:value]
I need to see the value of `ctx->cookie` right after line 341 in ngx_http_userid_get_uid where the cookie is parsed
[/REQUEST:value]
"""
    requests = extract_requests_in_chat(request_text)
    assert len(requests) == 1

    request = requests[0]

    assert request.type == LLMRequestType.RUNTIME_VALUE
    assert request.targets == [
        "I need to see the value of `ctx->cookie` right after line 341 in ngx_http_userid_get_uid where the cookie is parsed"
    ]
    assert (
        request.raw
        == "I need to see the value of `ctx->cookie` right after line 341 in ngx_http_userid_get_uid where the cookie is parsed"
    )


def test_java_definition_extract_requests_in_chat():
    request_text = "[REQUEST:java_definition] (name:`some_method`) (class:`some_class`) [/REQUEST:java_definition]"

    requests = extract_requests_in_chat(request_text)
    assert len(requests) == 1

    request = requests[0]

    assert request.type == LLMRequestType.JAVA_DEFINITION
    assert request.targets == ["(name:`some_method`) (class:`some_class`)"]
    assert request.raw == "(name:`some_method`) (class:`some_class`)"


def test_extract_requests_in_chat_against_duplicate_tags():
    request_text = """[REQUEST:definition] some text [REQUEST:definition] (name:`ngx_http_userid_set_uid`) [/REQUEST:definition] [REQUEST:definition] [REQUEST:reference] (name:`ctx->cookie`) [/REQUEST:reference]"""

    requests = extract_requests_in_chat(request_text)

    for request in requests:
        print(request)

    assert len(requests) == 2

    assert requests[0].type == LLMRequestType.DEFINITION
    assert requests[0].targets == ["ngx_http_userid_set_uid"]
    assert requests[0].raw == "(name:`ngx_http_userid_set_uid`)"

    assert requests[1].type == LLMRequestType.REFERENCE
    assert requests[1].targets == ["ctx->cookie"]
    assert requests[1].raw == "(name:`ctx->cookie`)"

    request_text = """[REQUEST:definition] some text [REQUEST:definition] some text [REQUEST:definition] (name:`ngx_http_userid_set_uid`) [/REQUEST:definition] [REQUEST:definition]"""

    requests = extract_requests_in_chat(request_text)

    for request in requests:
        print(request)

    assert len(requests) == 1

    assert requests[0].type == LLMRequestType.DEFINITION
    assert requests[0].targets == ["ngx_http_userid_set_uid"]
    assert requests[0].raw == "(name:`ngx_http_userid_set_uid`)"


@pytest.mark.slow
def test_definition_handler(
    detection_c_asc_nginx_cpv_10: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_10,
    ).build(
        previous_action=HeadAction(),
    )

    test_snippet = """*filepath: src/http/modules/ngx_http_userid_filter_module.c
30:typedef struct {
31:    ngx_uint_t  enable;
32:    ngx_uint_t  flags;
33:
34:    ngx_int_t   service;
35:
36:    ngx_str_t   name;
37:    ngx_str_t   domain;
38:    ngx_str_t   path;
39:    ngx_str_t   p3p;
40:
41:    time_t      expires;
42:
43:    u_char      mark;
44:} ngx_http_userid_conf_t;

"""

    request = LLMRequest(
        type=LLMRequestType.DEFINITION,
        targets=["ngx_http_userid_conf_t"],
        raw="Need to see the definition of the structure that holds the userid configuration (name:`ngx_http_userid_conf_t`)",
    )

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_10[0], Path(tmp_dir), "c"
        )

        definition_handler = DefinitionRequestHandler(context, code_inspector)

        assert test_snippet == definition_handler.handle_request(request)


def test_java_definition_handler(
    detection_jvm_mock_java_cpv_0: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_jvm_mock_java_cpv_0,
    ).build(
        previous_action=HeadAction(),
    )

    test_snippet = """*filepath: src/main/java/com/aixcc/mock_java/App.java
12:    public static void executeCommand(String data) {
13:        //Only "ls", "pwd", and "echo" commands are allowed.
14:        try{
15:            ProcessBuilder processBuilder = new ProcessBuilder();
16:            processBuilder.command(data);
17:            Process process = processBuilder.start();
18:            process.waitFor();
19:        } catch (Exception e) {
20:            e.printStackTrace();
21:        }
22:    }\n\n"""

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_jvm_mock_java_cpv_0[0], Path(tmp_dir), "c"
        )

        java_definition_handler = JavaDefinitionRequestHandler(context, code_inspector)

        request = LLMRequest(
            type=LLMRequestType.JAVA_DEFINITION,
            targets=["(name:`executeCommand`) (class:`App`)"],
            raw="(name:`executeCommand`) (class:`App`)",
        )

        assert (
            java_definition_handler.handle_request(request)
            == 'You are using the "java_definition" type request on the C/C++ project. This type of request is only allowed for Java projects. Check the "Information Request" section again.\n\n'
        )

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_jvm_mock_java_cpv_0[0], Path(tmp_dir), "jvm"
        )

        java_definition_handler = JavaDefinitionRequestHandler(context, code_inspector)

        assert test_snippet == java_definition_handler.handle_request(
            LLMRequest(
                type=LLMRequestType.JAVA_DEFINITION,
                targets=["(name:`executeCommand`) (class:`App`)"],
                raw="(name:`executeCommand`) (class:`App`)",
            )
        )

        assert (
            java_definition_handler.handle_request(
                LLMRequest(
                    type=LLMRequestType.JAVA_DEFINITION,
                    targets=[
                        "(name:`executeCommand`) (class:`App`) (invalid:`invalid`)"
                    ],
                    raw="(name:`executeCommand`) (class:`App`) (invalid:`invalid`)",
                )
            )
            == """Your request "(name:`executeCommand`) (class:`App`) (invalid:`invalid`)" contains invalid syntax regarding "['invalid']". Check the "Information Request" section again and fix your request accordingly.\n\n"""
        )

        assert (
            java_definition_handler.handle_request(
                LLMRequest(
                    type=LLMRequestType.JAVA_DEFINITION,
                    targets=["(name:`executeCommand`)"],
                    raw="(name:`executeCommand`)",
                )
            )
            == """The request "(name:`executeCommand`)" contains no (class:`target class`) or more than one (class:`target class`). You must contain only one (class:`target class`) within the [REQUEST:java_definition] ... [REQUEST:java_definition] tag. Check the "Information Request" section again.\n\n"""
        )

        assert (
            java_definition_handler.handle_request(
                LLMRequest(
                    type=LLMRequestType.JAVA_DEFINITION,
                    targets=["(class:`App`)"],
                    raw="(class:`App`)",
                )
            )
            == """The request "(class:`App`)" contains no (name:`target name`) or more than one (name:`target name`). You must contain only one (name:`target name`) within the [REQUEST:java_definition] ... [REQUEST:java_definition] tag. Check the "Information Request" section again.\n\n"""
        )

        assert (
            java_definition_handler.handle_request(
                LLMRequest(
                    type=LLMRequestType.JAVA_DEFINITION,
                    targets=["(name:`com.app.executeCommand`) (class:`com.app.App`)"],
                    raw="(name:`com.app.executeCommand`) (class:`com.app.App`)",
                )
            )
            == """In your request "(name:`com.app.executeCommand`) (class:`com.app.App`)", the `com.app.executeCommand` looks like a fully qualified name. Check the "Information Request" section again and submit the request with a simple name accordingly.\n\n"""
        )

        assert (
            java_definition_handler.handle_request(
                LLMRequest(
                    type=LLMRequestType.JAVA_DEFINITION,
                    targets=["(name:`executeCommand`) (class:`invalid_class`)"],
                    raw="(name:`executeCommand`) (class:`invalid_class`)",
                )
            )
            == """In your request "(name:`executeCommand`) (class:`invalid_class`)", it seems `invalid_class` does not exist in the project or is not available due to the failure of our information retrieval system. Make sure the `invalid_class` actually exists in the project as it is, or try to proceed without the information if you are definitely sure about its existence.\n\n"""
        )

        assert (
            java_definition_handler.handle_request(
                LLMRequest(
                    type=LLMRequestType.JAVA_DEFINITION,
                    targets=["(name:`invalid_method`) (class:`App`)"],
                    raw="(name:`invalid_method`) (class:`App`)",
                )
            )
            == """In your request "(name:`invalid_method`) (class:`App`)", it seems `invalid_method` does not exist in the project or is not available due to the failure of our information retrieval system. Make sure the `invalid_method` actually exists in the project as it is, or try to proceed without the information if you are definitely sure about its existence.\n\n"""
        )


@pytest.mark.slow
def test_reference_handler(detection_c_asc_nginx_cpv_10: tuple[Path, Path]):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_10,
    ).build(
        previous_action=HeadAction(),
    )

    request = LLMRequest(
        type=LLMRequestType.REFERENCE,
        targets=["ctx->cookie"],
        raw="I need to see all references to `ctx->cookie` to ensure we catch all access points (name:`ctx->cookie`)",
    )

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_10[0], Path(tmp_dir), "c"
        )

        reference_handler = ReferenceRequestHandler(context, code_inspector)

        result = reference_handler.handle_request(request)

        assert (
            "ngx_http_userid_set_uid(ngx_http_request_t *r, ngx_http_userid_ctx_t *ctx,"
            in result
        )
        assert (
            "ngx_http_userid_get_uid(ngx_http_request_t *r, ngx_http_userid_conf_t *conf)"
            in result
        )
        assert (
            "ngx_http_userid_create_uid(ngx_http_request_t *r, ngx_http_userid_ctx_t *ctx,"
            in result
        )


@pytest.mark.slow
def test_reference_handler_invalid(
    detection_c_asc_nginx_cpv_10: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_10,
    ).build(
        previous_action=HeadAction(),
    )

    request = LLMRequest(
        type=LLMRequestType.REFERENCE,
        targets=["not_exist_code"],
        raw="This is an invalid request (name:`not_exist_code`)",
    )

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_10[0], Path(tmp_dir), "c"
        )

        reference_handler = ReferenceRequestHandler(context, code_inspector)

        assert (
            reference_handler.handle_request(request)
            == "It seems `not_exist_code` is not found in the codebase. Make sure you are asking the code element that actually exists in the codebase as it is."
        )


@pytest.mark.slow
def test_file_handler(detection_c_asc_nginx_cpv_10: tuple[Path, Path]):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_10,
    ).build(
        previous_action=HeadAction(),
    )

    file_head = """1:
2:/*
3: * Copyright (C) Igor Sysoev
4: * Copyright (C) Nginx, Inc.
5: */
6:
7:
8:#include <ngx_config.h>
9:#include <ngx_core.h>
10:#include <ngx_http.h>
"""

    file_tail = """901:}
902:
903:
904:static ngx_int_t
905:ngx_http_userid_init_worker(ngx_cycle_t *cycle)
906:{
907:    struct timeval  tp;
908:
909:    ngx_gettimeofday(&tp);
910:
911:    /* use the most significant usec part that fits to 16 bits */
912:    start_value = (((uint32_t) tp.tv_usec / 20) << 16) | ngx_pid;
913:
914:    return NGX_OK;
915:}
"""

    request_text = LLMRequest(
        type=LLMRequestType.FILE,
        targets=["src/http/modules/ngx_http_userid_filter_module.c"],
        raw="I need to inspect the entire userid filter module to understand the context (file:`src/http/modules/ngx_http_userid_filter_module.c`)",
    )

    file_request_handler = FileRequestHandler(context)

    result = file_request_handler.handle_request(request_text)

    assert file_head in result
    assert file_tail in result


def _construct_embed_cache_for_test(
    similar_code_request_handler: SimilarCodeRequestHandler, json_name: str
):
    with open(TEST_SNIPPET_DIRECTORY / json_name, "r") as f:
        test_embeddings = json.load(f)

    for embed_dict in test_embeddings:
        query_results = similar_code_request_handler.code_inspector.get_definition(
            embed_dict["name"], print_line=False
        )

        assert query_results is not None
        assert len(query_results) == 1

        query_result = query_results[0]

        embed_cache = SnippetEmbedCache(
            snippet_hash=hash(query_result.snippet.text),
            query_result=query_result,
            embed=embed_dict["embedding"],
        )

        similar_code_request_handler.embed_cache[embed_cache.snippet_hash] = embed_cache


@pytest.mark.slow
def test_get_embedding_from_query_result_nginx(
    detection_c_asc_nginx_cpv_10: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_10,
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_10[0], Path(tmp_dir), "c"
        )

        similar_code_request_handler = SimilarCodeRequestHandler(
            context, code_inspector, LlmApiManager.from_environment(model="gpt-4o")
        )

        _construct_embed_cache_for_test(similar_code_request_handler, "nginx.json")

        query_results = code_inspector.get_definition(
            "ngx_http_process_prefer", print_line=False
        )

        assert query_results is not None
        assert len(query_results) == 1

        target_query_results = code_inspector.get_definition(
            "ngx_http_process_prefer", print_line=False
        )

        assert target_query_results is not None

        query_results_for_similar = (
            similar_code_request_handler._get_N_similar_functions(  # pyright: ignore[reportPrivateUsage]
                target_query_results[0]
            )
        )

        assert len(query_results_for_similar) == 2


# @pytest.mark.vcr()
@pytest.mark.skip(
    "@TODO: cassette-related routine needs to be developed for code embeddings"
)
def test_similar_code_handler_in_nginx(
    detection_c_asc_nginx_cpv_10: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_10,
    ).build(
        previous_action=HeadAction(),
    )

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_10[0], Path(tmp_dir), "c"
        )

        # make records that visit files
        code_inspector.get_definition("ngx_http_process_prefer")
        code_inspector.get_definition("ngx_http_process_request_headers")
        code_inspector.get_definition("ngx_table_elt_t")
        code_inspector.get_definition("ngx_table_elt_s")
        code_inspector.get_definition("ngx_http_headers_in_t")

        similar_code_request_handler = SimilarCodeRequestHandler(
            context, code_inspector, LlmApiManager.from_environment(model="gpt-4o")
        )

        request = LLMRequest(
            type=LLMRequestType.SIMILAR,
            targets=["ngx_http_process_prefer"],
            raw="I need to inspect the similar functions `ngx_http_process_prefer` to understand the proper context (name:`ngx_http_process_prefer`).",
        )

        result = similar_code_request_handler.handle_request(request)

        assert "ngx_http_process_host" in result
        assert "ngx_http_process_from" in result


@pytest.mark.slow
def test_import_handler(detection_jvm_jenkins_cpv_1: tuple[Path, Path]):
    context, _ = AIxCCContextBuilder(
        *detection_jvm_jenkins_cpv_1,
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    request = LLMRequest(
        type=LLMRequestType.IMPORT,
        targets=["Script.java"],
        raw="Please show me the imports of the Script.java file (name:`Script.java`)",
    )

    import_handler = ImportRequestHandler(context)

    assert (
        import_handler.handle_request(request)
        in """Here are the import statements present in `plugins/toy-plugin/src/main/java/io/jenkins/plugins/toyplugin/Script.java`
filename:plugins/toy-plugin/src/main/java/io/jenkins/plugins/toyplugin/Script.java
25:package io.jenkins.plugins.toyplugin;
26:
27:import hudson.model.Job;
28:import javax.script.ScriptEngine;
29:import javax.script.ScriptEngineManager;
30:
31:import jenkins.model.Jenkins;
32:import jenkins.security.SecureRequester;
33:import org.codehaus.groovy.control.CompilationFailedException;
34:import org.kohsuke.stapler.QueryParameter;
35:import org.kohsuke.stapler.export.Exported;
36:import org.kohsuke.stapler.interceptor.RequirePOST;
37:import groovy.lang.GroovyClassLoader;
38:import org.codehaus.groovy.ast.ClassNode;
39:import org.codehaus.groovy.ast.CodeVisitorSupport;
40:import org.codehaus.groovy.ast.expr.MethodCallExpression;
41:import org.codehaus.groovy.ast.stmt.ExpressionStatement;
42:import org.codehaus.groovy.classgen.GeneratorContext;
43:import org.codehaus.groovy.control.CompilationUnit;
44:import org.codehaus.groovy.control.CompilationUnit.PrimaryClassNodeOperation;
45:import org.codehaus.groovy.control.CompilerConfiguration;
46:import org.codehaus.groovy.control.Phases;
47:import org.codehaus.groovy.control.SourceUnit;
48:import java.security.CodeSource;
49:import java.lang.reflect.Field;
50:import java.util.HashSet;
51:import java.util.Set;


"""
    )


def test_import_handler_c(detection_c_mock_cp_cpv_1: tuple[Path, Path]):
    context, _ = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    request = LLMRequest(
        type=LLMRequestType.IMPORT,
        targets=["mock_vp.c"],
        raw="(name:`mock_vp.c`)",
    )

    import_handler = ImportRequestHandler(context)

    assert (
        import_handler.handle_request(request)
        == 'You are using the "import" type request on the C/C++ source code (`mock_vp.c`). This type of request is only allowed for Java projects. Check the "Information Request" section again.\n\n'
    )


@pytest.mark.slow
def test_duplicate_requests(detection_c_asc_nginx_cpv_10: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_10,
    ).build(
        previous_action=HeadAction(),
    )

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_10[0], Path(tmp_dir), "c"
        )

        request_handler = RequestHandler(LlmApiManager.from_environment(model="gpt-4o"))
        request_handler.set_context(context)
        request_handler.init_handlers(context, code_inspector)

        mock_patch_state = PatchState(
            patch_stage=PatchStage.ANALYZE_ROOT_CAUSE,
            messages=[],
            diff=b"",
            detection=detection,
            requests=[
                LLMRequest(
                    type=LLMRequestType.DEFINITION,
                    targets=["not_exist_code"],
                    raw="This is an invalid request (name:`not_exist_code`)",
                ),
                LLMRequest(
                    type=LLMRequestType.DEFINITION,
                    targets=["not_exist_code"],
                    raw="duplicate request (name:`not_exist_code`)",
                ),
            ],
            action=HeadAction(),
            feedback_cnt=0,
        )

        assert (
            "has duplicate content with the previous request"
            in request_handler._handle_request(mock_patch_state)  # pyright: ignore[reportPrivateUsage]
        )


@pytest.mark.slow
def test_ctags_failure_requests(detection_c_r2_freerdp_cpv_1: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_r2_freerdp_cpv_1,
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_r2_freerdp_cpv_1[0], Path(tmp_dir), "c"
        )

        request_handler = RequestHandler(LlmApiManager.from_environment(model="gpt-4o"))
        request_handler.set_context(context)
        request_handler.init_handlers(context, code_inspector)

        mock_patch_state = PatchState(
            patch_stage=PatchStage.ANALYZE_ROOT_CAUSE,
            messages=[],
            diff=b"",
            detection=detection,
            requests=[
                LLMRequest(
                    type=LLMRequestType.DEFINITION,
                    targets=["CHANNEL_NAME_LEN"],
                    raw="(name:`CHANNEL_NAME_LEN`)",
                ),
            ],
            action=HeadAction(),
            feedback_cnt=0,
        )

        channel_name_len_result = """The definition of `CHANNEL_NAME_LEN` cannot be directly retrieved due to the internal failure.
Instead, I provide definition-likely snippets for `CHANNEL_NAME_LEN` as follows:

*filepath: winpr/include/winpr/wtsapi.h
70:#define CHANNEL_OPTION_COMPRESS 0x00400000
71:#define CHANNEL_OPTION_SHOW_PROTOCOL 0x00200000
72:#define CHANNEL_OPTION_REMOTE_CONTROL_PERSISTENT 0x00100000
73:
74:#define CHANNEL_MAX_COUNT 31
75:#define CHANNEL_NAME_LEN 7
76:
77:typedef struct tagCHANNEL_DEF
78:{
79:	char name[CHANNEL_NAME_LEN + 1];
80:	ULONG options;

"""

        assert (
            request_handler._handle_request(mock_patch_state) == channel_name_len_result  # pyright: ignore[reportPrivateUsage]
        )

        mock_patch_state = PatchState(
            patch_stage=PatchStage.ANALYZE_ROOT_CAUSE,
            messages=[],
            diff=b"",
            detection=detection,
            requests=[
                LLMRequest(
                    type=LLMRequestType.DEFINITION,
                    targets=["CHANNEL_DEF"],
                    raw="(name:`CHANNEL_NAME_LEN`)",
                ),
            ],
            action=HeadAction(),
            feedback_cnt=0,
        )

        channel_def_result = """The definition of `CHANNEL_DEF` cannot be directly retrieved due to the internal failure.
Instead, I provide definition-likely snippets for `CHANNEL_DEF` as follows:

*filepath: winpr/include/winpr/wtsapi.h
76:
77:typedef struct tagCHANNEL_DEF
78:{
79:	char name[CHANNEL_NAME_LEN + 1];
80:	ULONG options;
81:} CHANNEL_DEF;
82:typedef CHANNEL_DEF* PCHANNEL_DEF;
83:typedef PCHANNEL_DEF* PPCHANNEL_DEF;
84:
85:typedef struct tagCHANNEL_PDU_HEADER

*filepath: winpr/include/winpr/wtsapi.h
77:typedef struct tagCHANNEL_DEF
78:{
79:	char name[CHANNEL_NAME_LEN + 1];
80:	ULONG options;
81:} CHANNEL_DEF;
82:typedef CHANNEL_DEF* PCHANNEL_DEF;
83:typedef PCHANNEL_DEF* PPCHANNEL_DEF;
84:
85:typedef struct tagCHANNEL_PDU_HEADER
86:{

"""

        assert request_handler._handle_request(mock_patch_state) == channel_def_result  # pyright: ignore[reportPrivateUsage]


def test_line_request_handler(
    detection_c_mock_cp_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_mock_cp_cpv_1[0], Path(tmp_dir), "c"
        )

        line_request_handler = LineRequestHandler(context, code_inspector)

        assert (
            line_request_handler.handle_request(
                LLMRequest(
                    type=LLMRequestType.LINE,
                    targets=["(file:`mock_vp.c`) (line:3-7)"],
                    raw="(file:`mock_vp.c`) (line:3-7)",
                )
            )
            == """Regarding the request "(file:`mock_vp.c`) (line:3-7)", the `mock_vp.c` has not been found in the previous user-provided code information (i.e., "*filepath: ..." parts). Make SURE that the requested file is confirmed to **explicitly** exist in the previous request result.\n\n"""
        )

        # make records that visit files
        code_inspector.get_definition("func_b")

        assert (
            line_request_handler.handle_request(
                LLMRequest(
                    type=LLMRequestType.LINE,
                    targets=["(file:`/src/mock_vp.c`) (line:3-7)"],
                    raw="(file:`/src/mock_vp.c`) (line:3-7)",
                )
            )
            == """Your request "(file:`/src/mock_vp.c`) (line:3-7)" contains the absolute path for (file:`filename`) field. Submit a fixed request with a relative path according to the provided rule.\n\n"""
        )

        assert (
            line_request_handler.handle_request(
                LLMRequest(
                    type=LLMRequestType.LINE,
                    targets=["(file:`mock_vp.c`) (file:`mock_vp.c`) (line:3-7)"],
                    raw="(file:`mock_vp.c`) (file:`mock_vp.c`) (line:3-7)",
                )
            )
            == """Your request "(file:`mock_vp.c`) (file:`mock_vp.c`) (line:3-7)" contains more than one target file. You can request only one file per one request.\n\n"""
        )

        assert (
            line_request_handler.handle_request(
                LLMRequest(
                    type=LLMRequestType.LINE,
                    targets=["(file:`mock_vp1.c`) (line:3-7)"],
                    raw="(file:`mock_vp1.c`) (line:3-7)",
                )
            )
            == """Regarding the request "(file:`mock_vp1.c`) (line:3-7)", the `mock_vp1.c` has not been found in the previous user-provided code information (i.e., "*filepath: ..." parts). Make SURE that the requested file is confirmed to **explicitly** exist in the previous request result.\n\n"""
        )

        assert (
            line_request_handler.handle_request(
                LLMRequest(
                    type=LLMRequestType.LINE,
                    targets=["(file:`mock_vp.c`)"],
                    raw="(file:`mock_vp.c`)",
                )
            )
            == """Your request "(file:`mock_vp.c`)" does not contain a valid line range using the hyphen ('-'). Submit a fixed request according to the provided rule.\n\n"""
        )

        assert (
            line_request_handler.handle_request(
                LLMRequest(
                    type=LLMRequestType.LINE,
                    targets=["(file:`mock_vp.c`) (line:3-128)"],
                    raw="(file:`mock_vp.c`) (line:3-128)",
                )
            )
            == """Regarding the request "(file:`mock_vp.c`) (line:3-128)", the end line number (128) exceeds the maximum line number (41). Fix your request according to this information.\n\n"""
        )

        assert (
            line_request_handler.handle_request(
                LLMRequest(
                    type=LLMRequestType.LINE,
                    targets=["(file:`mock_vp.c`) (line:3-7)"],
                    raw="(file:`mock_vp.c`) (line:3-7)",
                )
            )
            == """*filepath: mock_vp.c
3:#include <unistd.h>
4:
5:char items[3][10];
6:
7:void func_a(){

"""
        )
