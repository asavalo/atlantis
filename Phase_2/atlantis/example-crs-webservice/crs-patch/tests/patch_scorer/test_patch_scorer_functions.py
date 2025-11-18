from pathlib import Path

from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.patch_scorer.functions import (
    _temporary_patched_file,  # pyright: ignore[reportPrivateUsage]
    source_and_patched_declarations,
)
from unidiff import PatchSet


def test_source_and_patched_declarations(
    detection_c_mock_cp_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    source_declarations, patched_declarations = next(
        source_and_patched_declarations(
            context,
            r"""--- a/mock_vp.c
+++ b/mock_vp.c
@@ -11,7 +11,7 @@
         printf("input item:");
         buff = &items[i][0];
         i++;
-        fgets(buff, 40, stdin);
+        fgets(buff, 10, stdin);
         buff[strcspn(buff, "\n")] = 0;
     }while(strlen(buff)!=0);
     i--;
""",
        )
    )

    assert (
        source_declarations
        == r"""void func_a(){
    char* buff;
    int i = 0;
    do{
        printf("input item:");
        buff = &items[i][0];
        i++;
        fgets(buff, 40, stdin);
        buff[strcspn(buff, "\n")] = 0;
    }while(strlen(buff)!=0);
    i--;
}"""
    )

    assert (
        patched_declarations
        == r"""void func_a(){
    char* buff;
    int i = 0;
    do{
        printf("input item:");
        buff = &items[i][0];
        i++;
        fgets(buff, 10, stdin);
        buff[strcspn(buff, "\n")] = 0;
    }while(strlen(buff)!=0);
    i--;
}"""
    )


def test_temporary_patched_file(
    detection_c_mock_cp_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    diff = r"""--- a/mock_vp.c
+++ b/mock_vp.c
@@ -11,7 +11,7 @@
         printf("input item:");
         buff = &items[i][0];
         i++;
-        fgets(buff, 40, stdin);
+        fgets(buff, 10, stdin);
         buff[strcspn(buff, "\n")] = 0;
     }while(strlen(buff)!=0);
     i--;
"""

    patch_set = PatchSet.from_string(diff)

    with _temporary_patched_file(
        patch_set[0], context["pool"].source_directory / "mock_vp.c"
    ) as patched_file:
        patched_content = patched_file.read_text()

        assert (
            patched_content
            == r"""#include <stdio.h>
#include <string.h>
#include <unistd.h>

char items[3][10];

void func_a(){
    char* buff;
    int i = 0;
    do{
        printf("input item:");
        buff = &items[i][0];
        i++;
        fgets(buff, 10, stdin);
        buff[strcspn(buff, "\n")] = 0;
    }while(strlen(buff)!=0);
    i--;
}

void func_b(){
    char *buff;
    printf("done adding items\n");
    int j;
    printf("display item #:");
    scanf("%d", &j);
    buff = &items[j][0];
    printf("item %d: %s\n", j, buff);
}

#ifndef ___TEST___
int main()
{

    func_a();

    func_b();


    return 0;
}
#endif
"""
        )
