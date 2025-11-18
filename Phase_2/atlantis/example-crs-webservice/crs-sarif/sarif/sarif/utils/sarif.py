from copy import deepcopy

from loguru import logger

from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as AIxCCSarif,
)
from sarif.validator.preprocess.info_extraction import extract_essential_info

_include_rules = [
    # codeql
    "cpp/constant-array-overflow",
    "cpp/integer-multiplication-cast-to-long",
    "cpp/multiplication-overflow-in-alloc",
    "cpp/overrunning-write",
    "cpp/path-injection",
    "cpp/access-memory-location-after-end-buffer-strlen",
    "cpp/invalid-pointer-deref",
    "cpp/memory-unsafe-function-scan",
    "cpp/off-by-one-array-access",
    "cpp/offset-use-before-range-check",
    "cpp/overrunning-write-with-float",
    "cpp/overrun-write",
    "cpp/sign-conversion-pointer-arithmetic",
    "cpp/type-confusion",
    "cpp/unbounded-write",
    "cpp/uncontrolled-allocation-size",
    "cpp/unsafe-strcat",
    "cpp/use-after-free",
    "java/command-line-injection",
    "java/command-line-injection-experimental",
    "java/concatenated-command-line",
    "java/concatenated-sql-query",
    "java/exec-tainted-environment",
    "java/file-path-injection",
    "java/improper-validation-of-array-index",
    "java/jython-injection",
    "java/ldap-injection",
    "java/log4j-injection",
    "java/partial-path-traversal",
    "java/path-injection",
    "java/regex-injection",
    "java/sql-injection",
    "java/ssrf",
    "java/tainted-arithmetic",
    "java/tainted-format-string",
    "java/unsafe-deserialization",
    "java/unsafe-eval",
    "java/user-controlled-bypass",
    "java/xml/xpath-injection",
    "java/xslt-injection",
    "java/xss",
    "java/xxe",
    "java/zipslip",
    # semgrep
    "cpp.lang.security.filesystem.path-manipulation.path-manipulation",
    "cpp.lang.security.strings.unbounded-copy-to-stack-buffer.unbounded-copy-to-stack-buffer",
    "java.lang.security.audit.command-injection-process-builder.command-injection-process-builder",
    "java.lang.security.audit.dangerous-groovy-shell.dangerous-groovy-shell",
    "java.lang.security.audit.formatted-sql-string.formatted-sql-string",
    "java.lang.security.audit.ldap-injection.ldap-injection",
    "java.lang.security.audit.object-deserialization.object-deserialization",
    "java.lang.security.audit.script-engine-injection.script-engine-injection",
    "java.lang.security.audit.sqli.jdbc-sqli.jdbc-sqli",
    "java.lang.security.audit.xml-custom-entityresolver.xml-custom-entityresolver",
    "java.lang.security.audit.xml-decoder.xml-decoder",
    "java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal",
    "java.servlets.security.httpservlet-path-traversal-deepsemgrep.httpservlet-path-traversal-deepsemgrep",
    "java.servlets.security.httpservlet-path-traversal.httpservlet-path-traversal",
    "java.servlets.security.servletresponse-writer-xss.servletresponse-writer-xss",
    "java.spring.security.injection.tainted-file-path.tainted-file-path",
    "java.spring.spring-tainted-path-traversal.spring-tainted-path-traversal",
    "cpp.lang.security.memory.allocation.tainted-allocation-size.tainted-allocation-size",
    "cpp.lang.security.memory.deallocation.double-delete.double-delete",
    "cpp.lang.security.memory.negative-return-value-array-index.negative-return-value-array-index",
    "cpp.lang.security.memory.null-deref.null-library-function.null-library-function",
    "cpp.lang.security.memory.unvalidated-array-index.unvalidated-array-index",
    "cpp.lang.security.strings.missing-nul-cpp-string-memcpy.missing-nul-cpp-string-memcpy",
    "cpp.lang.security.use-after-free.local-variable-malloc-free.local-variable-malloc-free",
    "cpp.lang.security.use-after-free.local-variable-new-delete.local-variable-new-delete",
    # snyk
    "cpp/BufferOverflow",
    "cpp/ImproperNullTermination",
    "cpp/IntegerOverflow",
    "cpp/NegativeIndex",
    "cpp/PT",
    "cpp/UnsafeFunctionStringHandling",
    "cpp/DerefNull",
    "cpp/DoubleFree",
    "cpp/UseAfterFree",
    "cpp/UserControlledPointer",
    "java/CodeInjection",
    "java/Deserialization",
    "java/IndirectCommandInjection",
    "java/LdapBadAuth",
    "java/LdapInjection",
    "java/PT",
    "java/Sqli",
    "java/Ssrf",
    "java/Xpath",
    # llm-poc-gen
    "FuzzerSecurityIssueCritical: OS Command Injection",
    "FuzzerSecurityIssueCritical: Integer Overflow",
    "FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)",
    "FuzzerSecurityIssueHigh: Remote Code Execution",
    "FuzzerSecurityIssueHigh: SQL Injection",
    "FuzzerSecurityIssueHigh: SQL Injection",
    "FuzzerSecurityIssueCritical: Remote JNDI Lookup",
    "FuzzerSecurityIssueCritical: LDAP Injection",
    "FuzzerSecurityIssueHigh: XPath Injection",
    "FuzzerSecurityIssueHigh: load arbitrary library",
    "FuzzerSecurityIssueLow: Regular Expression Injection",
    "FuzzerSecurityIssueCritical: Script Engine Injection",
    "FuzzerSecurityIssueCritical: File read/write hook path",
]


def _remove_unused_rules(sarif_dict: dict, rule_name: str):
    for run in sarif_dict["runs"]:
        run["tool"]["driver"]["rules"] = [
            rule for rule in run["tool"]["driver"]["rules"] if rule["id"] == rule_name
        ]
    return sarif_dict


def _remove_useless_fields(sarif_dict: dict) -> dict:
    for run in sarif_dict["runs"]:
        # Remove notifications from driver if present
        if "notifications" in run["tool"]["driver"]:
            run["tool"]["driver"].pop("notifications")

        # Remove unnecessary top-level fields
        for field in ["invocations", "artifacts", "properties"]:
            run.pop(field, None)  # Using pop with None avoids KeyError

    return sarif_dict


def split_sarif(sarif_dict: dict) -> list[AIxCCSarif]:
    sarif_dict = _remove_useless_fields(sarif_dict)

    # Create individual SARIF models for each result
    processed_sarifs = []
    for result in sarif_dict["runs"][0]["results"]:
        if result["ruleId"] in _include_rules:
            splitted_res = deepcopy(sarif_dict)
            splitted_res["runs"][0]["results"] = [result]
            splitted_res = _remove_unused_rules(splitted_res, result["ruleId"])
            processed_sarifs.append(AIxCCSarif(**splitted_res))

    logger.debug(f"Split results into {len(sarif_dict['runs'][0]['results'])} files")
    return processed_sarifs


def deduplicate_sarif(sarif_models: list[AIxCCSarif]) -> list[AIxCCSarif]:
    seen = set()
    deduplicated = []

    for model in sarif_models:
        info = extract_essential_info(model)
        if info not in seen:
            seen.add(info)
            deduplicated.append(model)
        else:
            logger.debug("Deduplicated SARIF model")

    return deduplicated
