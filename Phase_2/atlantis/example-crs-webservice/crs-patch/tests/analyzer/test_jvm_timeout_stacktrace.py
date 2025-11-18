from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.analyzer.services.jvm_timeout_stacktrace import (
    JVMTimeoutStacktraceAnalyzer,
)
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.mock import MockEvaluator

from tests.common.utils import compare_portable_text


@pytest.mark.slow(reason="Should trigger timeout")
def test_jstack_at_timeout_analyzer(
    detection_jvm_r2_apache_commons_compress_diff_1_cpv_0: tuple[Path, Path],
):
    expected_main_thread_stacktrace = b"""java.lang.Thread.State: RUNNABLE
        at java.math.MutableBigInteger.divideOneWord(java.base@17.0.2/MutableBigInteger.java:1138)
        at java.math.MutableBigInteger.divideKnuth(java.base@17.0.2/MutableBigInteger.java:1208)
        at java.math.MutableBigInteger.divideKnuth(java.base@17.0.2/MutableBigInteger.java:1168)
        at java.math.BigInteger.divideAndRemainderKnuth(java.base@17.0.2/BigInteger.java:2346)
        at java.math.BigInteger.divideAndRemainder(java.base@17.0.2/BigInteger.java:2334)
        at java.math.BigDecimal.createAndStripZerosToMatchScale(java.base@17.0.2/BigDecimal.java:4904)
        at java.math.BigDecimal.divideAndRound(java.base@17.0.2/BigDecimal.java:4793)
        at java.math.BigDecimal.divide(java.base@17.0.2/BigDecimal.java:5206)
        at java.math.BigDecimal.divide(java.base@17.0.2/BigDecimal.java:1832)
        at java.math.BigDecimal.divideToIntegralValue(java.base@17.0.2/BigDecimal.java:1868)
        at java.math.BigDecimal.divideAndRemainder(java.base@17.0.2/BigDecimal.java:2024)
        at java.math.BigDecimal.remainder(java.base@17.0.2/BigDecimal.java:1966)
        at org.apache.commons.compress.archivers.tar.TarArchiveEntry.parseInstantFromDecimalSeconds(TarArchiveEntry.java:277)
        at org.apache.commons.compress.archivers.tar.TarArchiveEntry.processPaxHeader(TarArchiveEntry.java:1603)
        at org.apache.commons.compress.archivers.tar.TarArchiveEntry.updateEntryFromPaxHeaders(TarArchiveEntry.java:1946)
        at org.apache.commons.compress.archivers.tar.TarFile.applyPaxHeadersToCurrentEntry(TarFile.java:326)
        at org.apache.commons.compress.archivers.tar.TarFile.paxHeaders(TarFile.java:605)
        at org.apache.commons.compress.archivers.tar.TarFile.getNextTarEntry(TarFile.java:510)
        at org.apache.commons.compress.archivers.tar.TarFile.<init>(TarFile.java:314)
        at org.apache.commons.compress.archivers.tar.TarFile.<init>(TarFile.java:290)
        at org.apache.commons.compress.archivers.tar.TarFile.<init>(TarFile.java:191)
        at CompressTarFuzzer.fuzzerTestOneInput(CompressTarFuzzer.java:28)
        at java.lang.invoke.LambdaForm$DMH/0x0000000800cb8c00.invokeStaticInit(java.base@17.0.2/LambdaForm$DMH)
        at java.lang.invoke.LambdaForm$MH/0x0000000800cb9c00.invoke(java.base@17.0.2/LambdaForm$MH)
        at java.lang.invoke.LambdaForm$MH/0x0000000800cb9400.invoke_MT(java.base@17.0.2/LambdaForm$MH)
        at com.code_intelligence.jazzer.driver.FuzzTargetRunner.runOne(FuzzTargetRunner.java:234)
        at com.code_intelligence.jazzer.runtime.FuzzTargetRunnerNatives.startLibFuzzer(Native Method)
        at com.code_intelligence.jazzer.driver.FuzzTargetRunner.startLibFuzzer(FuzzTargetRunner.java:551)
        at com.code_intelligence.jazzer.driver.FuzzTargetRunner.startLibFuzzer(FuzzTargetRunner.java:441)
        at com.code_intelligence.jazzer.driver.Driver.start(Driver.java:166)
        at com.code_intelligence.jazzer.Jazzer.start(Jazzer.java:118)
        at com.code_intelligence.jazzer.Jazzer.main(Jazzer.java:77)"""
    context, detection = AIxCCContextBuilder(
        *detection_jvm_r2_apache_commons_compress_diff_1_cpv_0,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    jstack_output = JVMTimeoutStacktraceAnalyzer().analyze(context, detection)
    assert jstack_output is not None
    assert compare_portable_text(expected_main_thread_stacktrace, jstack_output)
