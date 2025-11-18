import os

import pytest

from sarif.context import init_context
from sarif.models import CP
from sarif.utils.decorators import measure_time
from sarif.validator.preprocess.info_extraction import (
    __get_func_by_line_codeql,
    __get_func_by_line_joern,
    _get_func_name_by_line,
)

c_line_dict = [
    {"input": ("src/core/nginx.c", 215), "expected": "main"},
    {"input": ("src/core/nginx.c", 249), "expected": "main"},
    {"input": ("src/core/nginx.c", 225), "expected": "main"},
    {"input": ("src/core/nginx.c", 439), "expected": "ngx_show_version_info"},
    {"input": ("src/core/nginx.c", 517), "expected": "ngx_add_inherited_sockets"},
    {"input": ("src/core/nginx.c", 619), "expected": "ngx_set_environment"},
    {"input": ("src/core/nginx.c", 525), "expected": "ngx_add_inherited_sockets"},
    {"input": ("src/core/ngx_md5.c", 37), "expected": "ngx_md5_update"},
    {"input": ("src/core/ngx_md5.c", 22), "expected": "ngx_md5_init"},
    {"input": ("src/core/ngx_md5.c", 180), "expected": "ngx_md5_body"},
    {"input": ("src/core/ngx_md5.c", 257), "expected": "ngx_md5_body"},
    {"input": ("src/core/ngx_parse.c", 32), "expected": "ngx_parse_size"},
    {"input": ("src/core/ngx_parse.c", 118), "expected": "ngx_parse_time"},
    {"input": ("src/core/ngx_parse.c", 71), "expected": "ngx_parse_offset"},
]


java_line_dict = [
    {
        "input": (
            "cp-java-jenkins-source/jenkins/core/src/main/java/jenkins/org/apache/commons/validator/routines/DomainValidator.java",
            287,
        ),
        "expected": "isValid",
    },
    {
        "input": (
            "cp-java-jenkins-source/jenkins/core/src/main/java/jenkins/org/apache/commons/validator/routines/DomainValidator.java",
            329,
        ),
        "expected": "isValidTld",
    },
    {
        "input": (
            "cp-java-jenkins-source/jenkins/core/src/main/java/jenkins/org/apache/commons/validator/routines/DomainValidator.java",
            344,
        ),
        "expected": "isValidInfrastructureTld",
    },
    {
        "input": (
            "cp-java-jenkins-source/jenkins/core/src/main/java/jenkins/org/apache/commons/validator/routines/DomainValidator.java",
            216,
        ),
        "expected": "<init>",
    },
    {
        "input": (
            "cp-java-jenkins-source/jenkins/core/src/main/java/jenkins/org/apache/commons/validator/routines/DomainValidator.java",
            2129,
        ),
        "expected": "updateTLDOverride",
    },
    {
        "input": (
            "cp-java-jenkins-source/jenkins/core/src/main/java/jenkins/ProxyInjector.java",
            52,
        ),
        "expected": "injectMembers",
    },
    {
        "input": (
            "cp-java-jenkins-source/jenkins/core/src/main/java/jenkins/ProxyInjector.java",
            53,
        ),
        "expected": "injectMembers",
    },
    {
        "input": (
            "cp-java-jenkins-source/jenkins/core/src/main/java/jenkins/ProxyInjector.java",
            54,
        ),
        "expected": "injectMembers",
    },
]


class TestGetFunctionNameByLine:

    @pytest.mark.parametrize(
        "file_path,line_number,expected",
        [
            (item["input"][0], item["input"][1], item["expected"])
            for item in c_line_dict
        ],
    )
    def test_get_func_name_by_line_c(
        self, c_cp: CP, file_path: str, line_number: int, expected: str
    ):
        init_context(cp=c_cp, env_mode="local", debug_mode="debug")
        res = _get_func_name_by_line(file_path, line_number)
        assert res == expected

    @pytest.mark.parametrize(
        "file_path,line_number,expected",
        [
            (item["input"][0], item["input"][1], item["expected"])
            for item in java_line_dict
        ],
    )
    def test_get_func_name_by_line_java(
        self, jenkins_cp: CP, file_path: str, line_number: int, expected: str
    ):
        init_context(cp=jenkins_cp, env_mode="local", debug_mode="debug")
        res = _get_func_name_by_line(file_path, line_number)
        assert res == expected

    @pytest.mark.parametrize(
        "file_path,line_number,expected",
        [
            (item["input"][0], item["input"][1], item["expected"])
            for item in c_line_dict
        ],
    )
    @measure_time
    def test_get_func_name_by_line_joern_c(
        self, c_cp: CP, file_path: str, line_number: int, expected: str
    ):
        init_context(cp=c_cp, env_mode="local", debug_mode="debug")
        res = __get_func_by_line_joern(file_path, line_number)
        assert res == expected

    @pytest.mark.parametrize(
        "file_path,line_number,expected",
        [
            (item["input"][0], item["input"][1], item["expected"])
            for item in java_line_dict
        ],
    )
    @measure_time
    def test_get_func_name_by_line_joern_java(
        self, jenkins_cp: CP, file_path: str, line_number: int, expected: str
    ):
        init_context(cp=jenkins_cp, env_mode="local", debug_mode="debug")
        res = __get_func_by_line_joern(file_path, line_number)
        assert res == expected

    @pytest.mark.parametrize(
        "file_path,line_number,expected",
        [
            (item["input"][0], item["input"][1], item["expected"])
            for item in c_line_dict
        ],
    )
    @measure_time
    def test_get_func_name_by_line_codeql_c(
        self, c_cp: CP, file_path: str, line_number: int, expected: str
    ):
        init_context(cp=c_cp, env_mode="local", debug_mode="debug")
        res = __get_func_by_line_codeql(file_path, line_number)
        assert res == expected

    @pytest.mark.parametrize(
        "file_path,line_number,expected",
        [
            (item["input"][0], item["input"][1], item["expected"])
            for item in java_line_dict
        ],
    )
    @measure_time
    def test_get_func_name_by_line_codeql_java(
        self, jenkins_cp: CP, file_path: str, line_number: int, expected: str
    ):
        init_context(cp=jenkins_cp, env_mode="local", debug_mode="debug")
        res = __get_func_by_line_codeql(file_path, line_number)
        assert res == expected
