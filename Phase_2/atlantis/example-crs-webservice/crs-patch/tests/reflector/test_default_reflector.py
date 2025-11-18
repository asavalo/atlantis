import pytest
from crete.atoms.action import Action, HeadAction, VulnerableDiffAction
from crete.framework.reflector.services.default import DefaultReflector
from python_llm.api.actors import LlmApiManager


@pytest.mark.vcr()
def test_default_reflector():
    vulnerable_diff = rb"""diff --git target.c target.c
index 5b3bc13..fa47910 100644
--- target.c
+++ target.c
@@ -1,4 +1,4 @@
 int main() {
-  char buf[100];
+  char buf[200];
   strcpy(buf, argv[1]);
 }
"""

    stdout = b""
    stderr = b"Segmentation fault"

    reflector = DefaultReflector(
        llm_api_manager=LlmApiManager.from_environment(model="gpt-4o"),
    )
    previous_actions: list[Action] = [
        HeadAction(),
        VulnerableDiffAction(
            diff=vulnerable_diff,
            stdout=stdout,
            stderr=stderr,
        ),
    ]
    prompt = reflector.reflect(previous_actions)
    assert prompt is not None

    # We expect the reflection should advise the user to use 'strncpy' instead of 'strcpy'.
    assert "strncpy" in prompt
