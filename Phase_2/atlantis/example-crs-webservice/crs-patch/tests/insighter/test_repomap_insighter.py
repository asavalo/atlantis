from pathlib import Path

from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment_pool.services.mock import MockEnvironmentPool
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.insighter.services.repo_map import RepoMapInsighter
from python_llm.api.actors import LlmApiManager

from tests.common.utils import mock_insighter_context


def test_mock_cp(detection_c_mock_cp_cpv_1: tuple[Path, Path]):
    expected_diff = r"""
.gitignore

Makefile

mock_vp.c:
│#include <stdio.h>
│#include <string.h>
│#include <unistd.h>
│
⋮
│
█void func_a(){
│    char* buff;
│    int i = 0;
│    do{
│        printf("input item:");
│        buff = &items[i][0];
│        i++;
│        fgets(buff, 40, stdin);
│        buff[strcspn(buff, "\n")] = 0;
│    }while(strlen(buff)!=0);
│    i--;
│}
│
█void func_b(){
│    char *buff;
│    printf("done adding items\n");
│    int j;
│    printf("display item #:");
│    scanf("%d", &j);
│    buff = &items[j][0];
│    printf("item %d: %s\n", j, buff);
│}
│
│#ifndef ___TEST___
█int main()
│{
│
│    func_a();
│
│    func_b();
│
⋮
│    return 0;
│}
│#endif
"""

    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DummyEvaluator(),
        pool=MockEnvironmentPool(*detection_c_mock_cp_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    assert (
        RepoMapInsighter(
            llm_api_manager=LlmApiManager.from_environment(model="gpt-4o"),
            target_files=[],
        ).create(mock_insighter_context(context), detection)
        == expected_diff
    )
