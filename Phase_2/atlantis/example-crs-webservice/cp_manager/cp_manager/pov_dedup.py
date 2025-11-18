import re
import hashlib
from enum import Enum
from typing import Tuple, Optional
from pydantic import BaseModel

MAX_CALLSTACK_LEN = 50
class C_SANITIZER(Enum):
    HEAP_BOF = "AddressSanitizer: heap-buffer-overflow"
    UAF = "AddressSanitizer: heap-use-after-free"
    UAP = "AddressSanitizer: use-after-poison"
    DOUBLE_FREE = "AddressSanitizer: double-free"

    DYNAMIC_STACK_BOF = "AddressSanitizer: dynamic-stack-buffer-overflow"
    DYNAMIC_STACK_UBF = "AddressSanitizer: dynamic-stack-buffer-underflow"
    STACK_BOF = "AddressSanitizer: stack-buffer-overflow"
    STACK_UAR = "AddressSanitizer: stack-use-after-return"
    STACK_UAS = "AddressSanitizer: stack-use-after-scope"
    STACK_UBF = "AddressSanitizer: stack-buffer-underflow"

    GLOBAL_BOF = "AddressSanitizer: global-buffer-overflow"

    NEGATIVE_SIZE_PARAM = "AddressSanitizer: negative-size-param"
    INITIALIZATION_ORDER_FIASCO = "AddressSanitizer: initialization-order-fiasco"
    CONTAINER_OVERFLOW = "AddressSanitizer: container-overflow"
    INTRA_OBJECT_OVERFLOW = "AddressSanitizer: intra-object-overflow"
    INVALID_PTR_PAIR = "AddressSanitizer: invalid-pointer-pair"
    MEM_PARAM_OVERLAP = "AddressSanitizer: memcpy-param-overlap"
    STACK_OVERFLOW = "AddressSanitizer: stack-overflow"

    ABRT = "AddressSanitizer: ABRT"
    FPE = "AddressSanitizer: FPE"
    ILL = "AddressSanitizer: ILL"
    SEGV = "AddressSanitizer: SEGV"
    EXIT = "ERROR: libFuzzer: fuzz target exited"
    TIMEOUT = "ERROR: libFuzzer: timeout after" ### MUST BE DIFFERENT FROM TIMEOUT IN JVM_SANITIZER
    OOM = "libFuzzer: out-of-memory"


class JVM_SANITIZER(Enum):
    TIMEOUT = "ERROR: libFuzzer: timeout" ### MUST BE DIFFERENT FROM TIMEOUT IN C_SANITIZER
    PATH_TRAVERSAL = "Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: File path traversal"
    LDAP_INJECTION = "Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: LDAP Injection"
    OS_CMD_INJECTION = "Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: OS Command Injection"
    REMOTE_JNDI_LOOKUP = "Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: Remote JNDI Lookup"
    SCRIPT_ENGINE_INJECTION = "Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: Script Engine Injection"
    LOAD_LIBRARY = "Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh: load arbitrary library"
    SQL_INJECTION = "Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh: SQL Injection"
    XPATH_INJECTION = "Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh: XPath Injection"
    RCE = "Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh: Remote Code Execution"
    REGEX_INJECTION = "Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Regular Expression Injection"
    SSRF = "Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium: Server Side Request Forgery"
    OOM = "Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Out of memory"
    STACK_OVERFLOW = "Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Stack overflow"


class FunCall(BaseModel):
    name: Optional[str]
    file: Optional[str]
    line: Optional[int]

    def __str__(self):
        ret = ""
        if self.name is not None:
            ret += self.name
        if self.file is not None:
            ret += f":{self.file}"
        if self.line is not None:
            ret += f":{self.line}"
        return ret

    def __hash__(self):
        return self.__str__().__hash__()

    def __eq__(self, other):
        return str(self) == str(other)


class CallStack(BaseModel):
    calls: list[FunCall]

    def __str__(self):
        ret = ""
        for idx, call in enumerate(self.calls):
            ret += f"#{idx} {call}\n"
        return ret.strip()

    def __hash__(self):
        return self.__str__().__hash__()

    def __eq__(self, other):
        return str(self) == str(other)

    def is_superset(self, other: "CallStack") -> bool:
        for call in other.calls:
            if call not in self.calls:
                return False
        return True


class CrashLog(BaseModel):
    callstacks: list[CallStack]
    sanitizer: Optional[C_SANITIZER | JVM_SANITIZER]

    def __str__(self):
        ret = "Sanitizer: " + str(self.sanitizer) + "\n"
        for idx, callstack in enumerate(self.callstacks):
            ret += "=" * 80 + "\n"
            ret += f"#{idx} callstack\n"
            ret += "=" * 80 + "\n"
            ret += f"{callstack}\n"
        return ret.strip()

    def unique_key(self) -> str:
        return hashlib.sha256(str(self).encode()).hexdigest()

    def __hash__(self):
        return self.unique_key().__hash__()

    def __eq__(self, other):
        return self.unique_key() == other.unique_key()


def get_filtered_crash_log(crash_log: bytes, is_jvm: bool) -> CrashLog:
    if is_jvm:

        def is_interesting_call(call: FunCall) -> bool:
            if None in [call.name, call.file, call.line]:
                return False
            if (
                call.name.startswith("java.base")
                or "0x" in call.name
                or "$" in call.name
            ):
                return False
            return True

        return __get_filtered_crash_log(
            crash_log, parse_crash_log_jvm, is_interesting_call, is_jvm
        )
    else:

        def is_interesting_call(call: FunCall) -> bool:
            if None in [call.name, call.file, call.line]:
                return False
            if call.file.startswith("/src/llvm-project"):
                return False
            return True

        return __get_filtered_crash_log(
            crash_log, parse_crash_log_c, is_interesting_call, is_jvm
        )


def __get_filtered_crash_log(
    crash_log: bytes, parse_func, is_interesting_call, is_jvm: bool
) -> CrashLog:
    crash_log = parse_func(crash_log)

    fuzz_file_name = extract_fuzz_file_name(crash_log, is_jvm)
    filtered_callstacks = []
    for callstack in crash_log.callstacks:
        filtered_calls = []
        for call in callstack.calls:
            if (
                is_interesting_call(call)
                and call.file != fuzz_file_name
                and call not in filtered_calls
            ):
                filtered_calls.append(call)
        filtered_callstacks.append(CallStack(calls=filtered_calls[:MAX_CALLSTACK_LEN]))
    return CrashLog(callstacks=filtered_callstacks, sanitizer=crash_log.sanitizer)


def extract_fuzz_file_name(crash_log: CrashLog, is_jvm: bool) -> str:
    KEY = "fuzzerTestOneInput" if is_jvm else "LLVMFuzzerTestOneInput"
    for callstack in crash_log.callstacks:
        for call in callstack.calls:
            if call.name is not None and KEY in call.name:
                return call.file
    return None


def parse_crash_log(crash_log: bytes, is_jvm: bool) -> CrashLog:
    if is_jvm:
        return parse_crash_log_jvm(crash_log)
    else:
        return parse_crash_log_c(crash_log)


def parse_sanitizer_key(crash_log: bytes, enum_class):
    for key in enum_class:
        if bytes(key.value, "utf-8") in crash_log:
            return key
    return None


def parse_crash_log_c(crash_log: bytes) -> CrashLog:
    sanitizer = parse_sanitizer_key(crash_log, C_SANITIZER)

    START = b"    #0 "
    callstacks = []
    chunks = crash_log.split(START)
    for chunk in chunks[1:]:
        chunk = START + chunk
        callstack = []
        for line in chunk.split(b"\n"):
            if line.startswith(b"    #"):
                line = line.decode("utf-8", errors="ignore")
                call = parse_fun_call_c(line)
                callstack.append(call)
            else:
                break
        callstacks.append(CallStack(calls=callstack))

    return CrashLog(callstacks=callstacks, sanitizer=sanitizer)


def parse_fun_call_c(line: str) -> FunCall:
    IN = " in "
    if IN in line:
        line = line.split(IN)[1]
        name = parse_func_name_c(line)
        line = line[len(name) :].strip()
        if "(BuildId: " in line or line.startswith("("):
            return FunCall(name=name, file=None, line=None)
        else:
            tmp = line.split(":")
            linenum = 0
            try:
                linenum = int(tmp[1])
            except:
                linenum = 0
            return FunCall(name=name, file=tmp[0], line=linenum)
    return FunCall(name=None, file=None, line=None)


def parse_func_name_c(line: str) -> str:
    ret = ""
    paren_cnt = 0
    for x in line:
        if x == "(":
            paren_cnt += 1
        elif x == ")":
            paren_cnt -= 1
        elif paren_cnt == 0 and x == " ":
            break
        ret += x
    return ret


def parse_crash_log_jvm(crash_log: bytes) -> CrashLog:
    sanitizer = parse_sanitizer_key(crash_log, JVM_SANITIZER)
    callstacks = []
    if sanitizer is JVM_SANITIZER.TIMEOUT:
        timeout_bytes = bytes(JVM_SANITIZER.TIMEOUT.value, "utf-8")
        crash_log = crash_log.split(timeout_bytes)[-1]
        crash_log = timeout_bytes + crash_log
        for log in crash_log.split(b"\r\n\r\n"):
            callstack = parse_callstack_jvm(log)
            if len(callstack.calls) > 0:
                callstacks.append(callstack)
    else:
        SPLIT = b"== Java Exception: "
        crash_log = crash_log.split(SPLIT)[-1]
        crash_log = SPLIT + crash_log
        callstacks.append(parse_callstack_jvm(crash_log))

    return CrashLog(callstacks=callstacks, sanitizer=sanitizer)


def parse_callstack_jvm(crash_log: bytes) -> CallStack:
    callstacks = []
    START = "\tat "
    for line in crash_log.split(b"\n"):
        line = line.decode("utf-8", errors="ignore")
        if line.startswith(START):
            line = line[len(START) :]
            call = parse_fun_call_jvm(line)
            callstacks.append(call)
    return CallStack(calls=callstacks)


def parse_fun_call_jvm(line: str) -> FunCall:
    if "(" in line:
        name = line.split("(")[0]
        line = line[len(name) + 1 :]
        if ")" in line:
            line = line.split(")")[0]
            if ":" in line:
                tmp = line.split(":")
                file_name = tmp[0]
                linenum = 0
                try:
                    linenum = int(tmp[1])
                except:
                    linenum = 0
                return FunCall(name=name, file=file_name, line=linenum)
            return FunCall(name=name, file=None, line=None)
    return FunCall(name=None, file=None, line=None)


def worth_to_check_crash(crash_log: CrashLog) -> bool:
    for callstack in crash_log.callstacks:
        if len(callstack.calls) > 0:
            return True
    return False

# return submit, update_group, group_id, crash_log
def dedup_crash_log(
    crash_groups: dict[int, list[CrashLog]], crash_log: bytes, is_jvm: bool
) -> Tuple[bool, int, CrashLog]:
    crash_log = get_filtered_crash_log(crash_log, is_jvm)
    if not worth_to_check_crash(crash_log):
        return False, False, -1, crash_log
    unique_key = crash_log.unique_key()
    for group_id, prev_crash_logs in crash_groups.items():
        for prev_crash_log in prev_crash_logs:
            if prev_crash_log.unique_key() == unique_key:
                return False, False, -1, crash_log
    for group_id, prev_crash_logs in crash_groups.items():
        if is_matched_crash(prev_crash_logs, crash_log):
            return (
                is_unseen_sanitizer(prev_crash_logs, crash_log),
                True,
                group_id,
                crash_log,
            )
    return True, True, len(crash_groups), crash_log


def is_matched_crash(prev_crash_logs: list[CrashLog], crash_log: CrashLog) -> bool:
    if try_match_double_free(prev_crash_logs, crash_log):
        return True
    if try_match_uaf(prev_crash_logs, crash_log):
        return True

    for prev_crash_log in prev_crash_logs:
        if prev_crash_log.sanitizer == crash_log.sanitizer:
            if is_similar_callstack(
                prev_crash_log.callstacks,
                crash_log.callstacks,
                prev_crash_log.sanitizer,
            ):
                return True
        elif not_eq_but_similar_sanitizer(
            crash_log.sanitizer, prev_crash_log.sanitizer
        ):
            if prev_crash_log.callstacks == crash_log.callstacks:
                return True
            if crash_log.sanitizer is None:
                if is_subset_callstack(prev_crash_log.callstacks, crash_log.callstacks):
                    return True
    return False

def try_match_double_free(prev_crash_logs: list[CrashLog], crash_log: CrashLog) -> bool:
    return __try_match_helper(prev_crash_logs, crash_log, C_SANITIZER.DOUBLE_FREE, 3, 2)

def try_match_uaf(prev_crash_logs: list[CrashLog], crash_log: CrashLog) -> bool:
    return __try_match_helper(prev_crash_logs, crash_log, C_SANITIZER.UAF, 3, 2)

def __try_match_helper(prev_crash_logs: list[CrashLog], crash_log: CrashLog, target_sanitizer, total, target_match) -> bool:
    sanitizer = crash_log.sanitizer
    if sanitizer is not target_sanitizer:
        return False
    callstacks = crash_log.callstacks
    if len(callstacks) == total:
        cnt = 0
        for idx in range(total):
            if has_same_callstack(prev_crash_logs, idx, callstacks[idx], sanitizer):
                cnt += 1
            if cnt == target_match:
                return True
    return False

def has_same_callstack(prev_crash_logs: list[CrashLog], idx: int, callstack: CallStack, sanitizer) -> bool:
    for prev_crash_log in prev_crash_logs:
        if prev_crash_log.sanitizer != sanitizer:
            continue
        prev_callstacks = prev_crash_log.callstacks
        if len(prev_callstacks) > idx:
            if prev_callstacks[idx] == callstack:
                return True
    return False


def get_n_subcallstacks(callstacks: list[CallStack], n: int) -> list[CallStack]:
    return list(map(lambda x: CallStack(calls=x.calls[n:]), callstacks))


def is_unseen_sanitizer(prev_crash_logs: list[CrashLog], crash_log: CrashLog) -> bool:
    for prev_crash_log in prev_crash_logs:
        if same_group_sanitizer(prev_crash_log.sanitizer, crash_log.sanitizer):
            return False
        if prev_crash_log.sanitizer is JVM_SANITIZER.RCE:
            prev_callstacks = get_n_subcallstacks(prev_crash_log.callstacks, 3)
            if prev_callstacks == crash_log.callstacks:
                return False
    return crash_log.sanitizer is not None


SIMILAR_SANITIZER = [
    [None, C_SANITIZER.EXIT],
    [C_SANITIZER.ILL, C_SANITIZER.SEGV],
    [C_SANITIZER.DOUBLE_FREE, C_SANITIZER.UAP, C_SANITIZER.UAF],
]


def same_group_sanitizer(s1, s2) -> bool:
    if s1 == s2:
        return True
    for group in SIMILAR_SANITIZER:
        if s1 in group and s2 in group:
            return True
    return False


def not_eq_but_similar_sanitizer(s1, s2) -> bool:
    if None in [s1, s2]:
        return True
    return same_group_sanitizer(s1, s2)


def is_subset_callstack(big: list[CallStack], small: list[CallStack]) -> bool:
    for s in small:
        tmp = False
        for b in big:
            if b.is_superset(s):
                tmp = True
                break
        if not tmp:
            return False
    return True


def is_similar_callstack(
    prev_callstacks: list[CallStack],
    crash_callstacks: list[CallStack],
    sanitizer: Optional[C_SANITIZER | JVM_SANITIZER],
) -> bool:
    threshold = 0.1
    if sanitizer is None:
        threshold = 0.25
    elif sanitizer in [C_SANITIZER.UAF, C_SANITIZER.DOUBLE_FREE]:
        # Callstacks of free and alloc are similar
        if is_subset_callstack(prev_callstacks[1:], crash_callstacks[1:]):
            return True
        # Callstacks of use/free and free are similar
        if is_subset_callstack(prev_callstacks[:2], crash_callstacks[:2]):
            return True
    elif sanitizer is C_SANITIZER.HEAP_BOF:
        # Callstacks of overflow are similar
        if is_subset_callstack(prev_callstacks[:1], crash_callstacks[:1]):
            return True
    return __is_similar_callstack(prev_callstacks, crash_callstacks, threshold)

def __is_similar_callstack(prev_callstacks: list[CallStack], crash_callstacks: list[CallStack], threshold: float) -> bool:
    if len(prev_callstacks) != len(crash_callstacks):
        return False
    for prev_callstack, crash_callstack in zip(prev_callstacks, crash_callstacks):
        set1 = set(map(lambda x: x.name, get_unique_funcalls([prev_callstack])))
        set2 = set(map(lambda x: x.name, get_unique_funcalls([crash_callstack])))
        min_len = min(len(set1), len(set2))
        threshold = int(min_len * threshold)
        if not (len(set1 - set2) <= threshold or len(set2 - set1) <= threshold):
            return False
    return True


def get_unique_funcalls(callstacks: list[CallStack]) -> set[FunCall]:
    ret = set()
    for callstack in callstacks:
        for call in callstack.calls:
            ret.add(call)
    return ret
