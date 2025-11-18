from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.insighter.services.crash_log_with_source import (
    CrashLogWithSourceInsighter,
)

from tests.common.utils import compare_portable_text, mock_insighter_context


@pytest.mark.vcr()
def test_mock_cp(detection_c_mock_cp_cpv_0: tuple[Path, Path]):
    expected_insight = r"""==ERROR: AddressSanitizer: global-buffer-overflow on address 0x5606a367cb5e at pc 0x5606a2b532d5 bp 0x7fff40771870 sp 0x7fff40771038
WRITE of size 38 at 0x5606a367cb5e thread T0
SCARINESS: 45 (multi-byte-write-global-buffer-overflow)
    #0 0x5606a2b532d4 in fgets /src/llvm-project/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:1207:5
    #1 0x5606a2c0c867 in func_a /src/fuzz/../mock-cp-src/mock_vp.c:14:9

mock_vp.c:14 in func_a
       10 |     do{
       11 |         printf("input item:");
       12 |         buff = &items[i][0];
       13 |         i++;
 =>    14 |         fgets(buff, 40, stdin);
       15 |         buff[strcspn(buff, "\n")] = 0;
       16 |     }while(strlen(buff)!=0);
       17 |     i--;
       18 | }

    #2 0x5606a2c0cdd9 in LLVMFuzzerTestOneInput /src/fuzz/filein_harness.c:57:3
    #3 0x5606a2ac1320 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #4 0x5606a2aac595 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
    #5 0x5606a2ab202f in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
    #6 0x5606a2add2d2 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #7 0x7fc51e884082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 5792732f783158c66fb4f3756458ca24e46e827d)
    #8 0x5606a2aa477d in _start (/out/filein_harness+0x3e77d)

DEDUP_TOKEN: ___interceptor_fgets--func_a--LLVMFuzzerTestOneInput
0x5606a367cb5e is located 34 bytes before global variable 'pipefd' defined in '/src/fuzz/filein_harness.c:9' (0x5606a367cb80) of size 8
0x5606a367cb5e is located 0 bytes after global variable 'items' defined in '/src/fuzz/../mock-cp-src/mock_vp.c:5' (0x5606a367cb40) of size 30
SUMMARY: AddressSanitizer: global-buffer-overflow /src/fuzz/../mock-cp-src/mock_vp.c:14:9 in func_a
Shadow bytes around the buggy address:
  0x5606a367c880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x5606a367c900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x5606a367c980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x5606a367ca00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x5606a367ca80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x5606a367cb00: 00 00 00 00 00 00 00 00 00 00 00[06]f9 f9 f9 f9
  0x5606a367cb80: 00 f9 f9 f9 00 00 00 00 00 00 00 00 00 00 00 00
  0x5606a367cc00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x5606a367cc80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x5606a367cd00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x5606a367cd80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==14==ABORTING
"""

    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    actual_insight = CrashLogWithSourceInsighter().create(
        mock_insighter_context(context), detection
    )
    assert actual_insight is not None
    assert compare_portable_text(expected_insight, actual_insight)


@pytest.mark.vcr()
def test_mock_java(detection_jvm_mock_java_cpv_0: tuple[Path, Path]):
    expected_insight = r"""== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: OS Command Injection
Executing OS commands with attacker-controlled data can lead to remote code execution.
	at com.code_intelligence.jazzer.sanitizers.OsCommandInjection.processImplStartHook(OsCommandInjection.java:63)
	at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1110)
	at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1073)
	at com.aixcc.mock_java.App.executeCommand(App.java:17)

src/main/java/com/aixcc/mock_java/App.java:17 in executeCommand
       13 |         //Only "ls", "pwd", and "echo" commands are allowed.
       14 |         try{
       15 |             ProcessBuilder processBuilder = new ProcessBuilder();
       16 |             processBuilder.command(data);
 =>    17 |             Process process = processBuilder.start();
       18 |             process.waitFor();
       19 |         } catch (Exception e) {
       20 |             e.printStackTrace();
       21 |         }

	at OssFuzz1.fuzzerTestOneInput(OssFuzz1.java:13)
"""

    context, detection = AIxCCContextBuilder(
        *detection_jvm_mock_java_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    actual_insight = CrashLogWithSourceInsighter().create(
        mock_insighter_context(context), detection
    )
    assert actual_insight is not None
    assert compare_portable_text(expected_insight, actual_insight)
