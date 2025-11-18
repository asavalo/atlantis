import re
from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.analyzer.services.jvm_stackoverflow_stacktrace import (
    JVMStackOverflowStacktraceAnalyzer,
    deduplicate_consecutive_frames,
)
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.mock import MockEvaluator

from tests.common.utils import compare_portable_text


@pytest.mark.slow
def test_jvm_stackoverflow_stacktrace_analyzer(
    detection_jvm_xstream_cpv_0: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_jvm_xstream_cpv_0,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    out = JVMStackOverflowStacktraceAnalyzer().analyze(context, detection)

    assert out
    m = re.search(r"repeated (\d+) times", out)
    assert m
    repeat_count = int(m.group(1))
    assert compare_portable_text(
        f"""
  [1] java.util.HashMap$KeyIterator.<init> (HashMap.java:1,605)
  [2] java.util.HashMap$KeySet.iterator (HashMap.java:985)
  [3] java.util.HashSet.iterator (HashSet.java:174)
  [4] java.util.AbstractSet.hashCode (AbstractSet.java:120)
  [5] java.util.AbstractSet.hashCode (AbstractSet.java:124)
... (repeated {repeat_count} times)
  [{repeat_count + 5 + 1:,}] java.util.AbstractSet.hashCode (AbstractSet.java:124)
  [{repeat_count + 5 + 2:,}] java.util.HashMap.hash (HashMap.java:340)
  [{repeat_count + 5 + 3:,}] java.util.HashMap.put (HashMap.java:612)
  [{repeat_count + 5 + 4:,}] java.util.HashSet.add (HashSet.java:221)
  [{repeat_count + 5 + 5:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.addCurrentElementToCollection (CollectionConverter.java:102)
  [{repeat_count + 5 + 6:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.populateCollection (CollectionConverter.java:92)
  [{repeat_count + 5 + 7:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.populateCollection (CollectionConverter.java:86)
  [{repeat_count + 5 + 8:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.unmarshal (CollectionConverter.java:81)
  [{repeat_count + 5 + 9:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convert (TreeUnmarshaller.java:74)
  [{repeat_count + 5 + 10:,}] com.thoughtworks.xstream.core.AbstractReferenceUnmarshaller.convert (AbstractReferenceUnmarshaller.java:72)
  [{repeat_count + 5 + 11:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convertAnother (TreeUnmarshaller.java:68)
  [{repeat_count + 5 + 12:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convertAnother (TreeUnmarshaller.java:52)
  [{repeat_count + 5 + 13:,}] com.thoughtworks.xstream.converters.collections.AbstractCollectionConverter.readBareItem (AbstractCollectionConverter.java:132)
  [{repeat_count + 5 + 14:,}] com.thoughtworks.xstream.converters.collections.AbstractCollectionConverter.readItem (AbstractCollectionConverter.java:117)
  [{repeat_count + 5 + 15:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.addCurrentElementToCollection (CollectionConverter.java:99)
  [{repeat_count + 5 + 16:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.populateCollection (CollectionConverter.java:92)
  [{repeat_count + 5 + 17:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.populateCollection (CollectionConverter.java:86)
  [{repeat_count + 5 + 18:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.unmarshal (CollectionConverter.java:81)
  [{repeat_count + 5 + 19:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convert (TreeUnmarshaller.java:74)
  [{repeat_count + 5 + 20:,}] com.thoughtworks.xstream.core.AbstractReferenceUnmarshaller.convert (AbstractReferenceUnmarshaller.java:72)
  [{repeat_count + 5 + 21:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convertAnother (TreeUnmarshaller.java:68)
  [{repeat_count + 5 + 22:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convertAnother (TreeUnmarshaller.java:52)
  [{repeat_count + 5 + 23:,}] com.thoughtworks.xstream.converters.collections.AbstractCollectionConverter.readBareItem (AbstractCollectionConverter.java:132)
  [{repeat_count + 5 + 24:,}] com.thoughtworks.xstream.converters.collections.AbstractCollectionConverter.readItem (AbstractCollectionConverter.java:117)
  [{repeat_count + 5 + 25:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.addCurrentElementToCollection (CollectionConverter.java:99)
  [{repeat_count + 5 + 26:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.populateCollection (CollectionConverter.java:92)
  [{repeat_count + 5 + 27:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.populateCollection (CollectionConverter.java:86)
  [{repeat_count + 5 + 28:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.unmarshal (CollectionConverter.java:81)
  [{repeat_count + 5 + 29:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convert (TreeUnmarshaller.java:74)
  [{repeat_count + 5 + 30:,}] com.thoughtworks.xstream.core.AbstractReferenceUnmarshaller.convert (AbstractReferenceUnmarshaller.java:72)
  [{repeat_count + 5 + 31:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convertAnother (TreeUnmarshaller.java:68)
  [{repeat_count + 5 + 32:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convertAnother (TreeUnmarshaller.java:52)
  [{repeat_count + 5 + 33:,}] com.thoughtworks.xstream.converters.collections.AbstractCollectionConverter.readBareItem (AbstractCollectionConverter.java:132)
  [{repeat_count + 5 + 34:,}] com.thoughtworks.xstream.converters.collections.AbstractCollectionConverter.readItem (AbstractCollectionConverter.java:117)
  [{repeat_count + 5 + 35:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.addCurrentElementToCollection (CollectionConverter.java:99)
  [{repeat_count + 5 + 36:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.populateCollection (CollectionConverter.java:92)
  [{repeat_count + 5 + 37:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.populateCollection (CollectionConverter.java:86)
  [{repeat_count + 5 + 38:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.unmarshal (CollectionConverter.java:81)
  [{repeat_count + 5 + 39:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convert (TreeUnmarshaller.java:74)
  [{repeat_count + 5 + 40:,}] com.thoughtworks.xstream.core.AbstractReferenceUnmarshaller.convert (AbstractReferenceUnmarshaller.java:72)
  [{repeat_count + 5 + 41:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convertAnother (TreeUnmarshaller.java:68)
  [{repeat_count + 5 + 42:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convertAnother (TreeUnmarshaller.java:52)
  [{repeat_count + 5 + 43:,}] com.thoughtworks.xstream.converters.collections.AbstractCollectionConverter.readBareItem (AbstractCollectionConverter.java:132)
  [{repeat_count + 5 + 44:,}] com.thoughtworks.xstream.converters.collections.AbstractCollectionConverter.readItem (AbstractCollectionConverter.java:117)
  [{repeat_count + 5 + 45:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.addCurrentElementToCollection (CollectionConverter.java:99)
  [{repeat_count + 5 + 46:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.populateCollection (CollectionConverter.java:92)
  [{repeat_count + 5 + 47:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.populateCollection (CollectionConverter.java:86)
  [{repeat_count + 5 + 48:,}] com.thoughtworks.xstream.converters.collections.CollectionConverter.unmarshal (CollectionConverter.java:81)
  [{repeat_count + 5 + 49:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convert (TreeUnmarshaller.java:74)
  [{repeat_count + 5 + 50:,}] com.thoughtworks.xstream.core.AbstractReferenceUnmarshaller.convert (AbstractReferenceUnmarshaller.java:72)
  [{repeat_count + 5 + 51:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convertAnother (TreeUnmarshaller.java:68)
  [{repeat_count + 5 + 52:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.convertAnother (TreeUnmarshaller.java:52)
  [{repeat_count + 5 + 53:,}] com.thoughtworks.xstream.core.TreeUnmarshaller.start (TreeUnmarshaller.java:136)
  [{repeat_count + 5 + 54:,}] com.thoughtworks.xstream.core.AbstractTreeMarshallingStrategy.unmarshal (AbstractTreeMarshallingStrategy.java:32)
  [{repeat_count + 5 + 55:,}] com.thoughtworks.xstream.XStream.unmarshal (XStream.java:1,469)
  [{repeat_count + 5 + 56:,}] com.thoughtworks.xstream.XStream.unmarshal (XStream.java:1,447)
  [{repeat_count + 5 + 57:,}] com.thoughtworks.xstream.XStream.fromXML (XStream.java:1,327)
  [{repeat_count + 5 + 58:,}] com.thoughtworks.xstream.XStream.fromXML (XStream.java:1,318)
  [{repeat_count + 5 + 59:,}] XmlFuzzer.fuzzerTestOneInput (XmlFuzzer.java:63)
  [{repeat_count + 5 + 60:,}] java.lang.invoke.LambdaForm$DMH/0x0000000800ba0440.invokeStaticInit (null)
  [{repeat_count + 5 + 61:,}] java.lang.invoke.LambdaForm$MH/0x0000000800c05840.invoke (null)
  [{repeat_count + 5 + 62:,}] java.lang.invoke.LambdaForm$MH/0x0000000800c06040.invoke_MT (null)
  [{repeat_count + 5 + 63:,}] com.code_intelligence.jazzer.driver.FuzzTargetRunner.runOne (FuzzTargetRunner.java:234)
  [{repeat_count + 5 + 64:,}] com.code_intelligence.jazzer.runtime.FuzzTargetRunnerNatives.startLibFuzzer (native method)
  [{repeat_count + 5 + 65:,}] com.code_intelligence.jazzer.driver.FuzzTargetRunner.startLibFuzzer (FuzzTargetRunner.java:551)
  [{repeat_count + 5 + 66:,}] com.code_intelligence.jazzer.driver.FuzzTargetRunner.startLibFuzzer (FuzzTargetRunner.java:441)
  [{repeat_count + 5 + 67:,}] com.code_intelligence.jazzer.driver.Driver.start (Driver.java:166)
  [{repeat_count + 5 + 68:,}] com.code_intelligence.jazzer.Jazzer.start (Jazzer.java:118)
  [{repeat_count + 5 + 69:,}] com.code_intelligence.jazzer.Jazzer.main (Jazzer.java:77)
""".strip("\n"),
        out,
    )


def test_deduplicate_consecutive_frames_cycle_size_1():
    raw_stacktrace = """
[1] path.to.class.method1 (file1.java:123)
[2] path.to.class.method2 (file2.java:123)
[3] path.to.class.method3 (file3.java:123)
[4] path.to.class.method4 (file4.java:123)
[5] path.to.class.method4 (file4.java:123)
[6] path.to.class.method4 (file4.java:123)
[7] path.to.class.method4 (file4.java:123)
[8] path.to.class.method4 (file4.java:123)
[9] path.to.class.method4 (file4.java:123)
[10] path.to.class.method4 (file4.java:123)
[11] path.to.class.method4 (file4.java:123)
[12] path.to.class.method4 (file4.java:123)
[13] path.to.class.method4 (file4.java:123)
[14] path.to.class.method4 (file4.java:123)
[15] path.to.class.method4 (file4.java:123)
[16] path.to.class.method4 (file4.java:123)
[17] path.to.class.method4 (file4.java:123)
[18] path.to.class.method4 (file4.java:123)
[19] path.to.class.method4 (file4.java:123)
[20] path.to.class.method5 (file5.java:123)
[21] path.to.class.method6 (file6.java:123)
""".strip()
    compact_stacktrace = deduplicate_consecutive_frames(raw_stacktrace)
    print(compact_stacktrace)
    assert (
        compact_stacktrace
        == """
[1] path.to.class.method1 (file1.java:123)
[2] path.to.class.method2 (file2.java:123)
[3] path.to.class.method3 (file3.java:123)
[4] path.to.class.method4 (file4.java:123)
... (repeated 14 times)
[19] path.to.class.method4 (file4.java:123)
[20] path.to.class.method5 (file5.java:123)
[21] path.to.class.method6 (file6.java:123)
""".strip()
    )


def test_deduplicate_consecutive_frames_cycle_size_3():
    raw_stacktrace = """
[1] path.to.class.method1 (file1.java:123)
[2] path.to.class.method2 (file2.java:123)
[3] path.to.class.method3 (file3.java:123)
[4] path.to.class.method4 (file4.java:123)
[5] path.to.class.method5 (file5.java:123)
[6] path.to.class.method6 (file6.java:123)
[7] path.to.class.method4 (file4.java:123)
[8] path.to.class.method5 (file5.java:123)
[9] path.to.class.method6 (file6.java:123)
[10] path.to.class.method4 (file4.java:123)
[11] path.to.class.method5 (file5.java:123)
[12] path.to.class.method6 (file6.java:123)
[13] path.to.class.method4 (file4.java:123)
[14] path.to.class.method5 (file5.java:123)
[15] path.to.class.method6 (file6.java:123)
[16] path.to.class.method4 (file4.java:123)
[17] path.to.class.method5 (file5.java:123)
[18] path.to.class.method6 (file6.java:123)
[19] path.to.class.method4 (file7.java:123)
[20] path.to.class.method5 (file8.java:123)
[21] path.to.class.method6 (file9.java:123)
""".strip()
    compact_stacktrace = deduplicate_consecutive_frames(raw_stacktrace)
    assert (
        compact_stacktrace
        == """
[1] path.to.class.method1 (file1.java:123)
[2] path.to.class.method2 (file2.java:123)
[3] path.to.class.method3 (file3.java:123)
[4] path.to.class.method4 (file4.java:123)
[5] path.to.class.method5 (file5.java:123)
[6] path.to.class.method6 (file6.java:123)
... (repeated 3 times)
[16] path.to.class.method4 (file4.java:123)
[17] path.to.class.method5 (file5.java:123)
[18] path.to.class.method6 (file6.java:123)
[19] path.to.class.method4 (file7.java:123)
[20] path.to.class.method5 (file8.java:123)
[21] path.to.class.method6 (file9.java:123)
""".strip()
    )
