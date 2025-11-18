from pathlib import Path

import pytest
from crete.commons.crash_analysis.functions.jazzer_crash import analyze_jazzer_crash
from crete.framework.fault_localizer.models import FaultLocation
from crete.framework.fault_localizer.services.stacktrace import (
    fault_locations_from_crash_stacks,
)

pov_stdout = b"""HARNESS_NAME=ActivemqOne   HARNESS_CLASSNAME=com.aixcc.activemq.harnesses.one.ActivemqOne Blob: /work/tmp_blob HARNESS_CP=/out/harnesses/one/jakarta.annotation-api-2.1.1.jar:/out/harnesses/one/activemq-all-6.2.0-SNAPSHOT.jar:/out/harnesses/one/activemq-harness.jar
DEDUP_TOKEN: 9bfdb9bbead12b19
jazzer exit=77

"""

pov_stderr = b"""OpenJDK 64-Bit Server VM warning: Option CriticalJNINatives was deprecated in version 16.0 and will likely be removed in a future release.
OpenJDK 64-Bit Server VM warning: Sharing is only supported for boot loader classes because bootstrap classpath has been appended
INFO: Not using the following disabled hooks: com.code_intelligence.jazzer.sanitizers.IntegerOverflow
INFO: Loaded 325 hooks from com.code_intelligence.jazzer.runtime.TraceCmpHooks
INFO: Loaded 5 hooks from com.code_intelligence.jazzer.runtime.TraceDivHooks
INFO: Loaded 2 hooks from com.code_intelligence.jazzer.runtime.TraceIndirHooks
INFO: Loaded 4 hooks from com.code_intelligence.jazzer.runtime.NativeLibHooks
INFO: Loaded 2 hooks from com.code_intelligence.jazzer.sanitizers.ClojureLangHooks
INFO: Loaded 5 hooks from com.code_intelligence.jazzer.sanitizers.Deserialization
INFO: Loaded 5 hooks from com.code_intelligence.jazzer.sanitizers.ExpressionLanguageInjection
INFO: Loaded 22 hooks from com.code_intelligence.jazzer.sanitizers.FileReadWrite
INFO: Loaded 22 hooks from com.code_intelligence.jazzer.sanitizers.FileSystemTraversal
INFO: Loaded 70 hooks from com.code_intelligence.jazzer.sanitizers.LdapInjection
INFO: Loaded 52 hooks from com.code_intelligence.jazzer.sanitizers.NamingContextLookup
INFO: Loaded 1 hooks from com.code_intelligence.jazzer.sanitizers.OsCommandInjection
INFO: Loaded 80 hooks from com.code_intelligence.jazzer.sanitizers.ReflectiveCall
INFO: Loaded 8 hooks from com.code_intelligence.jazzer.sanitizers.RegexInjection
INFO: Loaded 16 hooks from com.code_intelligence.jazzer.sanitizers.RegexRoadblocks
INFO: Loaded 12 hooks from com.code_intelligence.jazzer.sanitizers.ScriptEngineInjection
INFO: Loaded 3 hooks from com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery
INFO: Loaded 19 hooks from com.code_intelligence.jazzer.sanitizers.SqlInjection
INFO: Loaded 6 hooks from com.code_intelligence.jazzer.sanitizers.XPathInjection
INFO: Instrumented com.aixcc.activemq.harnesses.one.ActivemqOne (took 76 ms, size +28%)
INFO: using inputs from: /work/tmp_blob
INFO: found LLVMFuzzerCustomMutator (0x7fb685e39a00). Disabling -len_control by default.
INFO: libFuzzer ignores flags that start with '--'
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1591812605
INFO: Loaded 1 modules   (512 inline 8-bit counters): 512 [0x564204cbc1f0, 0x564204cbc3f0), 
INFO: Loaded 1 PC tables (512 PCs): 512 [0x564204c004f0,0x564204c024f0), 
jazzer: Running 1 inputs 1 time(s) each.
Running: /work/tmp_blob
INFO: Instrumented org.apache.activemq.openwire.OpenWireFormat (took 39 ms, size +23%)
INFO: Instrumented org.apache.activemq.wireformat.WireFormat (took 0 ms, size +0%)
INFO: Instrumented org.apache.activemq.util.DataByteArrayOutputStream (took 10 ms, size +18%)
INFO: Instrumented org.apache.activemq.util.DataByteArrayInputStream (took 10 ms, size +23%)
INFO: Instrumented org.apache.activemq.openwire.v11.MarshallerFactory (took 3 ms, size +8%)
INFO: Instrumented org.apache.activemq.openwire.DataStreamMarshaller (took 0 ms, size +0%)
INFO: New number of coverage counters: 1024
INFO: Instrumented org.apache.activemq.openwire.v11.ActiveMQBlobMessageMarshaller (took 3 ms, size +11%)
INFO: Instrumented org.apache.activemq.openwire.v11.ActiveMQMessageMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.MessageMarshaller (took 7 ms, size +14%)
INFO: Instrumented org.apache.activemq.openwire.v11.BaseCommandMarshaller (took 2 ms, size +12%)
INFO: New number of coverage counters: 2048
INFO: Instrumented org.apache.activemq.openwire.v11.BaseDataStreamMarshaller (took 22 ms, size +19%)
INFO: Instrumented org.apache.activemq.command.DataStructure (took 0 ms, size +0%)
INFO: Instrumented org.apache.activemq.openwire.v11.ActiveMQBytesMessageMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.ActiveMQMapMessageMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.ActiveMQObjectMessageMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.ActiveMQQueueMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.ActiveMQDestinationMarshaller (took 2 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v11.ActiveMQStreamMessageMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.ActiveMQTempQueueMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.ActiveMQTempDestinationMarshaller (took 2 ms, size +13%)
INFO: Instrumented org.apache.activemq.openwire.v11.ActiveMQTempTopicMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.ActiveMQTextMessageMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.ActiveMQTopicMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.BrokerIdMarshaller (took 3 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v11.BrokerInfoMarshaller (took 4 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.ConnectionControlMarshaller (took 16 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.ConnectionErrorMarshaller (took 5 ms, size +8%)
INFO: Instrumented org.apache.activemq.openwire.v11.ConnectionIdMarshaller (took 4 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v11.ConnectionInfoMarshaller (took 7 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.ConsumerControlMarshaller (took 7 ms, size +11%)
INFO: Instrumented org.apache.activemq.openwire.v11.ConsumerIdMarshaller (took 6 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v11.ConsumerInfoMarshaller (took 10 ms, size +13%)
INFO: Instrumented org.apache.activemq.openwire.v11.ControlCommandMarshaller (took 6 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v11.DataArrayResponseMarshaller (took 5 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.ResponseMarshaller (took 4 ms, size +11%)
INFO: Instrumented org.apache.activemq.openwire.v11.DataResponseMarshaller (took 6 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v11.DestinationInfoMarshaller (took 7 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v11.DiscoveryEventMarshaller (took 5 ms, size +11%)
INFO: Instrumented org.apache.activemq.openwire.v11.ExceptionResponseMarshaller (took 5 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v11.FlushCommandMarshaller (took 5 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.IntegerResponseMarshaller (took 4 ms, size +11%)
INFO: Instrumented org.apache.activemq.openwire.v11.JournalQueueAckMarshaller (took 4 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v11.JournalTopicAckMarshaller (took 5 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v11.JournalTraceMarshaller (took 5 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v11.JournalTransactionMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v11.KeepAliveInfoMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.LastPartialCommandMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.PartialCommandMarshaller (took 2 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v11.LocalTransactionIdMarshaller (took 2 ms, size +8%)
INFO: Instrumented org.apache.activemq.openwire.v11.TransactionIdMarshaller (took 1 ms, size +13%)
INFO: Instrumented org.apache.activemq.openwire.v11.MessageAckMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v11.MessageDispatchMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v11.MessageDispatchNotificationMarshaller (took 2 ms, size +8%)
INFO: New number of coverage counters: 4096
INFO: Instrumented org.apache.activemq.openwire.v11.MessageIdMarshaller (took 2 ms, size +8%)
INFO: Instrumented org.apache.activemq.openwire.v11.MessagePullMarshaller (took 2 ms, size +8%)
INFO: Instrumented org.apache.activemq.openwire.v11.NetworkBridgeFilterMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v11.ProducerAckMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v11.ProducerIdMarshaller (took 2 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v11.ProducerInfoMarshaller (took 3 ms, size +11%)
INFO: Instrumented org.apache.activemq.openwire.v11.RemoveInfoMarshaller (took 2 ms, size +8%)
INFO: Instrumented org.apache.activemq.openwire.v11.RemoveSubscriptionInfoMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v11.ReplayCommandMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.SessionIdMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v11.SessionInfoMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v11.ShutdownInfoMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v11.SubscriptionInfoMarshaller (took 2 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v11.TransactionInfoMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v11.WireFormatInfoMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v11.XATransactionIdMarshaller (took 2 ms, size +11%)
INFO: Instrumented org.apache.activemq.openwire.v10.MarshallerFactory (took 1 ms, size +8%)
INFO: Instrumented org.apache.activemq.openwire.v10.ActiveMQBlobMessageMarshaller (took 2 ms, size +11%)
INFO: Instrumented org.apache.activemq.openwire.v10.ActiveMQMessageMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.MessageMarshaller (took 4 ms, size +14%)
INFO: Instrumented org.apache.activemq.openwire.v10.BaseCommandMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.BaseDataStreamMarshaller (took 17 ms, size +19%)
INFO: Instrumented org.apache.activemq.openwire.v10.ActiveMQBytesMessageMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.ActiveMQMapMessageMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.ActiveMQObjectMessageMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.ActiveMQQueueMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.ActiveMQDestinationMarshaller (took 1 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v10.ActiveMQStreamMessageMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.ActiveMQTempQueueMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.ActiveMQTempDestinationMarshaller (took 1 ms, size +13%)
INFO: Instrumented org.apache.activemq.openwire.v10.ActiveMQTempTopicMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.ActiveMQTextMessageMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.ActiveMQTopicMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.BrokerIdMarshaller (took 2 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v10.BrokerInfoMarshaller (took 3 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.ConnectionControlMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.ConnectionErrorMarshaller (took 2 ms, size +8%)
INFO: Instrumented org.apache.activemq.openwire.v10.ConnectionIdMarshaller (took 1 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v10.ConnectionInfoMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.ConsumerControlMarshaller (took 2 ms, size +11%)
INFO: Instrumented org.apache.activemq.openwire.v10.ConsumerIdMarshaller (took 2 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v10.ConsumerInfoMarshaller (took 3 ms, size +13%)
INFO: Instrumented org.apache.activemq.openwire.v10.ControlCommandMarshaller (took 2 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v10.DataArrayResponseMarshaller (took 2 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.ResponseMarshaller (took 2 ms, size +11%)
INFO: Instrumented org.apache.activemq.openwire.v10.DataResponseMarshaller (took 1 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v10.DestinationInfoMarshaller (took 2 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v10.DiscoveryEventMarshaller (took 2 ms, size +11%)
INFO: Instrumented org.apache.activemq.openwire.v10.ExceptionResponseMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v10.FlushCommandMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.IntegerResponseMarshaller (took 1 ms, size +11%)
INFO: Instrumented org.apache.activemq.openwire.v10.JournalQueueAckMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v10.JournalTopicAckMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v10.JournalTraceMarshaller (took 2 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v10.JournalTransactionMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v10.KeepAliveInfoMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.LastPartialCommandMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.PartialCommandMarshaller (took 2 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v10.LocalTransactionIdMarshaller (took 2 ms, size +8%)
INFO: Instrumented org.apache.activemq.openwire.v10.TransactionIdMarshaller (took 1 ms, size +13%)
INFO: Instrumented org.apache.activemq.openwire.v10.MessageAckMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v10.MessageDispatchMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v10.MessageDispatchNotificationMarshaller (took 2 ms, size +8%)
INFO: Instrumented org.apache.activemq.openwire.v10.MessageIdMarshaller (took 2 ms, size +8%)
INFO: New number of coverage counters: 8192
INFO: Instrumented org.apache.activemq.openwire.v10.MessagePullMarshaller (took 2 ms, size +8%)
INFO: Instrumented org.apache.activemq.openwire.v10.NetworkBridgeFilterMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v10.ProducerAckMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v10.ProducerIdMarshaller (took 2 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v10.ProducerInfoMarshaller (took 2 ms, size +11%)
INFO: Instrumented org.apache.activemq.openwire.v10.RemoveInfoMarshaller (took 2 ms, size +8%)
INFO: Instrumented org.apache.activemq.openwire.v10.RemoveSubscriptionInfoMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v10.ReplayCommandMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.SessionIdMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v10.SessionInfoMarshaller (took 1 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v10.ShutdownInfoMarshaller (took 1 ms, size +12%)
INFO: Instrumented org.apache.activemq.openwire.v10.SubscriptionInfoMarshaller (took 2 ms, size +10%)
INFO: Instrumented org.apache.activemq.openwire.v10.TransactionInfoMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v10.WireFormatInfoMarshaller (took 2 ms, size +9%)
INFO: Instrumented org.apache.activemq.openwire.v10.XATransactionIdMarshaller (took 2 ms, size +11%)
INFO: Instrumented org.apache.activemq.command.ExceptionResponse (took 1 ms, size +8%)
INFO: Instrumented org.apache.activemq.command.Response (took 1 ms, size +7%)
INFO: Instrumented org.apache.activemq.command.BaseCommand (took 4 ms, size +8%)
INFO: Instrumented org.apache.activemq.command.Command (took 0 ms, size +0%)

== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh: Remote Code Execution
Unrestricted class/object creation based on externally controlled data may allow
remote code execution depending on available classes on the classpath.
	at jaz.Zer.reportFinding(Zer.java:108)
	at jaz.Zer.reportFindingIfEnabled(Zer.java:103)
	at jaz.Zer.<init>(Zer.java:80)
	at java.base/jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance0(Native Method)
	at java.base/jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:77)
	at java.base/jdk.internal.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
	at java.base/java.lang.reflect.Constructor.newInstanceWithCaller(Constructor.java:499)
	at java.base/java.lang.reflect.Constructor.newInstance(Constructor.java:480)
	at org.apache.activemq.openwire.v10.BaseDataStreamMarshaller.createThrowable(BaseDataStreamMarshaller.java:233)
	at org.apache.activemq.openwire.v10.BaseDataStreamMarshaller.looseUnmarsalThrowable(BaseDataStreamMarshaller.java:517)
	at org.apache.activemq.openwire.v10.ExceptionResponseMarshaller.looseUnmarshal(ExceptionResponseMarshaller.java:113)
	at org.apache.activemq.openwire.OpenWireFormat.doUnmarshal(OpenWireFormat.java:379)
	at org.apache.activemq.openwire.OpenWireFormat.unmarshal(OpenWireFormat.java:290)
	at com.aixcc.activemq.harnesses.one.ActivemqOne.fuzzerTestOneInput(ActivemqOne.java:38)
== libFuzzer crashing input ==
reproducer_path='.'; Java reproducer written to ./Crash_b689f32d11fe8df4749dba78d64e4fab43adcf7a.java


"""


@pytest.mark.slow
def test_stacktrace_fault_localizer(
    detection_jvm_activemq_cpv_0: tuple[Path, Path],
):
    source_directory, _ = detection_jvm_activemq_cpv_0

    crash_stacks = analyze_jazzer_crash(
        source_directory, pov_stdout + pov_stderr
    ).crash_stacks
    assert fault_locations_from_crash_stacks(crash_stacks) == [
        FaultLocation(
            file=source_directory
            / "activemq-client/src/main/java/org/apache/activemq/openwire/v10/BaseDataStreamMarshaller.java",
            function_name="createThrowable",
            line_range=(231, 232),
        ),
        FaultLocation(
            file=source_directory
            / "activemq-client/src/main/java/org/apache/activemq/openwire/v10/BaseDataStreamMarshaller.java",
            function_name="looseUnmarsalThrowable",
            line_range=(515, 516),
        ),
        FaultLocation(
            file=source_directory
            / "activemq-client/src/main/java/org/apache/activemq/openwire/v10/ExceptionResponseMarshaller.java",
            function_name="looseUnmarshal",
            line_range=(111, 112),
        ),
        FaultLocation(
            file=source_directory
            / "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java",
            function_name="doUnmarshal",
            line_range=(377, 378),
        ),
        FaultLocation(
            file=source_directory
            / "activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java",
            function_name="unmarshal",
            line_range=(288, 289),
        ),
    ]
