from pathlib import Path

import pytest
from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.environment.protocols import EnvironmentProtocol
from crete.framework.patch_pool.services.default import DefaultPatchPool

from tests.common.utils import build_aixcc_context


def _build_and_patch_environment(
    context: AgentContext, detection: Detection, patch: bytes
) -> EnvironmentProtocol:
    environment = context["pool"].restore(context)
    environment.patch(context, patch)
    environment.run_pov(context, detection)
    assert environment is not None
    return environment


@pytest.mark.slow
def test_save_and_load(
    detection_c_mock_cp_cpv_0: tuple[Path, Path], tmpdir_as_path: Path
):
    good_patch = r"""diff --git a/mock_vp.c b/mock_vp.c
index 9dc6bf0..72678be 100644
--- a/mock_vp.c
+++ b/mock_vp.c
@@ -10,7 +10,8 @@ func_a(){
         printf("input item:");
         buff = &items[i][0];
         i++;
-        fgets(buff, 40, stdin);
+        fgets(buff, 9, stdin);
+        if (i==3){buff[0]= 0;}
         buff[strcspn(buff, "\n")] = 0;
     }while(strlen(buff)!=0);
     i--;
"""
    tmpdir_as_path = Path("/tmp/crete-test-patch-pool")
    context, detection = build_aixcc_context(*detection_c_mock_cp_cpv_0)
    environment = _build_and_patch_environment(
        context, detection, good_patch.encode("utf-8", errors="ignore")
    )
    environment.run_pov(context, detection)

    pool = DefaultPatchPool(cache_directory=tmpdir_as_path)
    pool.save(context, good_patch)

    environment = pool.load(context, good_patch)
    assert environment is not None
    environment.run_pov(context, detection)
