from pathlib import Path

import pytest
from crete.atoms.action import HeadAction, SoundDiffAction
from crete.framework.agent.services.martian import (
    MartianAgent,
    _is_fuzzer_specific_patch,  # type: ignore
)
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.mock import MockEvaluator
from python_llm.api.actors import LlmApiManager

# NOTE: To pass mock-cp-cpv-2, CodeRover-K needs to be able to see not only
# functions but also variables.


@pytest.mark.integration
@pytest.mark.vcr()
def test_mock_c(detection_c_mock_c_cpv_0: tuple[Path, Path]):
    agent = MartianAgent(
        fault_localization_llm=LlmApiManager.from_environment(
            model="o4-mini", custom_llm_provider="openai"
        ),
        report_parser_llm=LlmApiManager.from_environment(
            model="gpt-4o", custom_llm_provider="openai"
        ),
        code_generation_llm=LlmApiManager.from_environment(
            model="claude-3-7-sonnet-20250219", custom_llm_provider="anthropic"
        ),
        backup_llm=LlmApiManager.from_environment(
            model="gemini-2.5-pro-preview-05-06",
            custom_llm_provider="openai",
        ),
        max_iterations=1,
    )

    context, detection = AIxCCContextBuilder(
        *detection_c_mock_c_cpv_0,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    action = next(agent.act(context, detection=detection))
    assert isinstance(action, SoundDiffAction)


@pytest.mark.integration
@pytest.mark.vcr()
def test_mock_java(detection_jvm_mock_java_cpv_0: tuple[Path, Path]):
    agent = MartianAgent(
        fault_localization_llm=LlmApiManager.from_environment(
            model="o4-mini", custom_llm_provider="openai"
        ),
        report_parser_llm=LlmApiManager.from_environment(
            model="gpt-4o", custom_llm_provider="openai"
        ),
        code_generation_llm=LlmApiManager.from_environment(
            model="claude-3-7-sonnet-20250219", custom_llm_provider="anthropic"
        ),
        backup_llm=LlmApiManager.from_environment(
            model="gemini-2.5-pro-preview-05-06",
            custom_llm_provider="openai",
        ),
        max_iterations=2,
    )

    context, detection = AIxCCContextBuilder(
        *detection_jvm_mock_java_cpv_0,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    action = next(agent.act(context, detection=detection))
    assert isinstance(action, SoundDiffAction)


def test_is_fuzzer_specific_patch():
    diff = """diff --git a/src/common-session.c b/src/common-session.c
index c9a76a0..3c97d59 100644
--- a/src/common-session.c
+++ b/src/common-session.c
@@ -174,20 +174,36 @@ void session_loop(void(*loophandler)(void)) {
 
 		dropbear_assert(ses.payload == NULL);
 
+#if DROPBEAR_FUZZ
+		int is_fuzzing = fuzz.fuzzing;
+#endif
+
 		/* We get woken up when signal handlers write to this pipe.
 		   SIGCHLD in svr-chansession is the only one currently. */
 #if DROPBEAR_FUZZ
-		if (!fuzz.fuzzing) 
+		if (!is_fuzzing) 
 #endif
 		{
 		FD_SET(ses.signal_pipe[0], &readfd);
 		}
 
 		/* set up for channels which can be read/written */
+#if DROPBEAR_FUZZ
+		if (!is_fuzzing) {
+			setchannelfds(&readfd, &writefd, writequeue_has_space);
+		}
+#else
 		setchannelfds(&readfd, &writefd, writequeue_has_space);
+#endif
 
 		/* Pending connections to test */
+#if DROPBEAR_FUZZ
+		if (!is_fuzzing) {
+			set_connect_fds(&writefd);
+		}
+#else
 		set_connect_fds(&writefd);
+#endif
 
 		/* We delay reading from the input socket during initial setup until
 		after we have written out our initial KEXINIT packet (empty writequeue). 
@@ -198,13 +214,27 @@ void session_loop(void(*loophandler)(void)) {
 		if (ses.sock_in != -1 
 			&& (ses.remoteident || isempty(&ses.writequeue)) 
 			&& writequeue_has_space) {
+#if DROPBEAR_FUZZ
+			/* In fuzzing mode, only add socket if it's a wrapped fd */
+			if (!is_fuzzing || (is_fuzzing && ses.sock_in >= 0)) {
+#endif
 			FD_SET(ses.sock_in, &readfd);
+#if DROPBEAR_FUZZ
+			}
+#endif
 		}
 
 		/* Ordering is important, this test must occur after any other function
 		might have queued packets (such as connection handlers) */
 		if (ses.sock_out != -1 && !isempty(&ses.writequeue)) {
+#if DROPBEAR_FUZZ
+			/* In fuzzing mode, only add socket if it's a wrapped fd */
+			if (!is_fuzzing || (is_fuzzing && ses.sock_out >= 0)) {
+#endif
 			FD_SET(ses.sock_out, &writefd);
+#if DROPBEAR_FUZZ
+			}
+#endif
 		}
 
 		val = select(ses.maxfd+1, &readfd, &writefd, NULL, &timeout);
@@ -230,7 +260,11 @@ void session_loop(void(*loophandler)(void)) {
 		any thing with the data, since the pipe's purpose is purely to
 		wake up the select() above. */
 		ses.channel_signal_pending = 0;
+#if DROPBEAR_FUZZ
+		if (!is_fuzzing && FD_ISSET(ses.signal_pipe[0], &readfd)) {
+#else
 		if (FD_ISSET(ses.signal_pipe[0], &readfd)) {
+#endif
 			char x;
 			TRACE(("signal pipe set"))
 			while (read(ses.signal_pipe[0], &x, 1) > 0) {}
@@ -262,7 +296,13 @@ void session_loop(void(*loophandler)(void)) {
 		were being held up during a KEX */
 		maybe_flush_reply_queue();
 
+#if DROPBEAR_FUZZ
+		if (!is_fuzzing) {
+			handle_connect_fds(&writefd);
+		}
+#else
 		handle_connect_fds(&writefd);
+#endif
 
 		/* loop handler prior to channelio, in case the server loophandler closes
 		channels on process exit */
@@ -270,7 +310,13 @@ void session_loop(void(*loophandler)(void)) {
 
 		/* process pipes etc for the channels, ses.dataallowed == 0
 		 * during rekeying ) */
+#if DROPBEAR_FUZZ
+		if (!is_fuzzing) {
+			channelio(&readfd, &writefd);
+		}
+#else
 		channelio(&readfd, &writefd);
+#endif
 
 		/* process session socket's outgoing data */
 		if (ses.sock_out != -1) {
"""
    assert _is_fuzzer_specific_patch(diff)
