import re
from pathlib import Path
from typing import Callable, List, TypedDict

import pytest
from crete.atoms.action import (
    Action,
    CompilableDiffAction,
    HeadAction,
    SoundDiffAction,
    UncompilableDiffAction,
    VulnerableDiffAction,
    WrongDiffAction,
)
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder


def _escape_ansi(line: bytes) -> bytes:
    ansi_escape = re.compile(rb"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub(b"", line)


class PatchCase(TypedDict):
    diff: bytes
    action_creator: Callable[[bytes], Action]


TEST_CASES: List[PatchCase] = [
    {
        "diff": rb"""diff --git a/mock_vp.c b/mock_vp.c
index 9dc6bf0..72678be 100644
--- a/mock_vp.c
+++ b/mock_vp.c
@@ -10,7 +10,8 @@ func_a(){
         printf("input item:");
         buff = &items[i][0];
         i++;
-        fgets(buff, 40, stdin);
+        fgets(buff, 9, stdin);
         buff[strcspn(buff, "\n")] = 0;
     }while(strlen(buff)!=0);
     i--;
""",
        "action_creator": lambda diff: WrongDiffAction(
            diff=diff,
            stdout=b"",
            stderr=b"error: corrupt patch at line 14\n",
        ),
    },
    {
        "diff": rb"""diff --git a/mock_vp.c b/mock_vp.c
index 9dc6bf0..72678be 100644
--- a/mock_vp.c
+++ b/mock_vp.c
@@ -10,6 +10,7 @@ func_a(){
         printf("input item:");
         buff = &items[i][0];
-        fgets(buff, 40, stdin);
+        fgets(buff, 9, stdin);
+        if (i==3){buff[0]= 0;}
         buff[strcspn(buff, "\n")] = 0;
     }while(strlen(buff)!=0);
     i--;
""",
        "action_creator": lambda diff: WrongDiffAction(
            diff=diff,
            stdout=b"",
            stderr=b"""error: patch failed: mock_vp.c:10
error: mock_vp.c: patch does not apply
""",
        ),
    },
    {
        "diff": rb"""diff --git a/mock_vp.c b/mock_vp.c
index 9dc6bf0..72678be 100644
--- a/mock_vp.c
+++ b/mock_vp.c
@@ -10,7 +10,8 @@ func_a(){
         printf("input item:");
         buff = &items[i][0];
         i++;
-        fgets(buff, 40, stdin);
+        fgets(buff, 9, stdin);
+        if (i==3){buff[0]= 0;  // Introduce a syntax error
         buff[strcspn(buff, "\n")] = 0;
     }while(strlen(buff)!=0);
     i--;
""",
        "action_creator": lambda diff: UncompilableDiffAction(
            diff=diff,
            stdout=b"error: expected 'while' in do/while loop",
            stderr=b"",
        ),
    },
    # TODO(oss-fuzz): functional test should be added
    #    {
    #        "diff": r"""diff --git a/mock_vp.c b/mock_vp.c
    # index 9dc6bf0..72678be 100644
    # --- a/mock_vp.c
    # +++ b/mock_vp.c
    # @@ -10,7 +10,8 @@ func_a(){
    #         printf("input item:");
    #         buff = &items[i][0];
    #         i++;
    # -        fgets(buff, 40, stdin);
    # +        fgets(buff, 9, stdin);
    # +        if (i==2){buff[0]= 0;}
    #         buff[strcspn(buff, "\n")] = 0;
    #     }while(strlen(buff)!=0);
    #     i--;
    # """,
    #        "action_creator": lambda diff: CompilableDiffAction(
    #            diff=diff,
    #            stdout=b"""FAILURE: test2 failed
    # Error in /usr/local/sbin/container_scripts/cmd_harness.sh from /usr/local/sbin/container_scripts/cp_tests: 2
    # """,
    #            stderr=b"",
    #        ),
    #    },
    {
        "diff": rb"""diff --git a/mock_vp.c b/mock_vp.c
index 9dc6bf0..72678be 100644
--- a/mock_vp.c
+++ b/mock_vp.c
@@ -10,7 +10,7 @@ func_a(){
         printf("input item:");
         buff = &items[i][0];
         i++;
-        fgets(buff, 40, stdin);
+        fgets(buff, 9, stdin);
         buff[strcspn(buff, "\n")] = 0;
     }while(strlen(buff)!=0);
     i--;
""",
        "action_creator": lambda diff: VulnerableDiffAction(
            diff=diff,
            stdout=b"ERROR: AddressSanitizer: SEGV on unknown address",
            stderr=b"",
        ),
    },
    {
        "diff": rb"""--- a/mock_vp.c
+++ b/mock_vp.c
@@ -8,10 +8,16 @@
     char* buff;
     int i = 0;
     do{
+        // Only continue if we have space in the array
+        if (i >= 3) {
+            printf("Maximum number of items reached\n");
+            break;
+        }
         printf("input item:");
         buff = &items[i][0];
         i++;
-        fgets(buff, 40, stdin);
+        // Limit reading to 9 characters to fit in the 10-byte buffer (including null terminator)
+        fgets(buff, 10, stdin);
         buff[strcspn(buff, "\n")] = 0;
     }while(strlen(buff)!=0);
     i--;
@@ -23,8 +29,13 @@
     int j;
     printf("display item #:");
     scanf("%d", &j);
-    buff = &items[j][0];
-    printf("item %d: %s\n", j, buff);
+    // Add bounds checking to prevent out-of-bounds access
+    if (j >= 0 && j < 3) {
+        buff = &items[j][0];
+        printf("item %d: %s\n", j, buff);
+    } else {
+        printf("Invalid item number: %d\n", j);
+    }
 }

 #ifndef ___TEST___
""",
        "action_creator": lambda diff: SoundDiffAction(diff=diff),
    },
]


def _compare_action(action: Action, expected_action: Action):
    assert type(action) is type(expected_action)

    match action, expected_action:
        case (
            VulnerableDiffAction(diff=diff, stdout=stdout, stderr=stderr),
            VulnerableDiffAction(
                diff=expected_diff, stdout=expected_stdout, stderr=expected_stderr
            ),
        ):
            assert diff == expected_diff
            assert expected_stdout in _escape_ansi(stdout)
            assert expected_stderr in _escape_ansi(stderr)
        case (
            CompilableDiffAction(diff=diff, stdout=stdout, stderr=stderr),
            CompilableDiffAction(
                diff=expected_diff, stdout=expected_stdout, stderr=expected_stderr
            ),
        ):
            assert diff == expected_diff
            assert expected_stdout in _escape_ansi(stdout)
            assert expected_stderr in _escape_ansi(stderr)
        case (
            UncompilableDiffAction(diff=diff, stdout=stdout, stderr=stderr),
            UncompilableDiffAction(
                diff=expected_diff, stdout=expected_stdout, stderr=expected_stderr
            ),
        ):
            assert diff == expected_diff
            assert expected_stdout in _escape_ansi(stdout)
            assert expected_stderr in _escape_ansi(stderr)
        case (
            WrongDiffAction(diff=diff, stdout=stdout, stderr=stderr),
            WrongDiffAction(
                diff=expected_diff, stdout=expected_stdout, stderr=expected_stderr
            ),
        ):
            assert diff == expected_diff
            assert expected_stdout in _escape_ansi(stdout)
            assert expected_stderr in _escape_ansi(stderr)
        case (SoundDiffAction(diff=diff), SoundDiffAction(diff=expected_diff)):
            assert diff == expected_diff
        case (HeadAction(), HeadAction()):
            pass
        case _:
            raise ValueError(f"Unexpected action type: {type(action)}")


@pytest.mark.integration
@pytest.mark.parametrize("test_case", TEST_CASES)
def test_evaluate(detection_c_mock_cp_cpv_1: tuple[Path, Path], test_case: PatchCase):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
    ).build(previous_action=HeadAction())

    action = context["evaluator"].evaluate(context, test_case["diff"], detection)
    expected_action = test_case["action_creator"](test_case["diff"])

    _compare_action(action, expected_action)
