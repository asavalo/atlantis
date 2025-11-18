import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

from langchain_core.messages.ai import AIMessage
from langchain_openai import ChatOpenAI
from vuli.delta import Delta
from vuli.model_manager import ModelManager


@patch.object(ModelManager, "_invoke")
def test_get_sinks(handler_1):
    def mock_1(*args, **kwargs) -> Any:
        return AIMessage(
            content="""
```json
[
    {"hunk_number": 1, "line_number_in_hunk": 29, "vulnerability_type": "Infinite loop", "related_code": "i = serverAddr.indexOf(':');"}
]
```"""
        )

    handler_1.side_effect = mock_1
    ModelManager().clear()
    ModelManager().add_model(
        lambda input, output: input * 0.0000025 + output * 0.00001,
        "gpt-4o",
        ChatOpenAI(api_key="tmp", base_url="url", model="mock", temperature=1.0),
    )
    content = """diff --git a/zookeeper-server/src/main/java/org/apache/zookeeper/server/util/MessageTracker.java b/zookeeper-server/src/main/java/org/apache/zookeeper/server/util/MessageTracker.java
index a81a12b..91952ca 100644
--- a/zookeeper-server/src/main/java/org/apache/zookeeper/server/util/MessageTracker.java
+++ b/zookeeper-server/src/main/java/org/apache/zookeeper/server/util/MessageTracker.java
@@ -105,7 +105,9 @@ private static void logMessages(
         CircularBuffer<BufferedMessage> messages,
         Direction direction) {
         String sentOrReceivedText = direction == Direction.SENT ? "sentBuffer to" : "receivedBuffer from";
-
+        if (serverAddr.contains(":")) {
+            verifyIPv6(serverAddr);
+        }
         if (messages.isEmpty()) {
             LOG.info("No buffered timestamps for messages {} {}", sentOrReceivedText, serverAddr);
         } else {
@@ -116,6 +118,34 @@ private static void logMessages(
         }
     }

+    private static void verifyIPv6(String serverAddr) {
+        int maxColons = 8;
+        int cntColons = 0;
+        int i = serverAddr.indexOf(':');
+        while (i > -1 && i < serverAddr.length() && cntColons < maxColons) {
+            cntColons++;
+            i = serverAddr.indexOf(':', i + 1);
+        }
+        //is there an extra?
+        int extraColons = countExtraColons(i, serverAddr);
+        //count extras
+        if (cntColons > 0 && (cntColons < maxColons || extraColons == 0)) {
+            return;
+        }
+        throw new IllegalArgumentException("bad ipv6: " + serverAddr + " too many colons=" + extraColons);
+    }
+
+    private static int countExtraColons(int i, String serverAddr) {
+        if (i == -1) {
+            return 1;
+        }
+        int cnt = 1;
+        while (i > 0) {
+            cnt++;
+            i = serverAddr.indexOf(':');
+        }
+        return cnt;
+    }
     /**
      * Direction for message track.
      */
diff --git a/zookeeper-server/src/test/java/org/apache/zookeeper/server/util/MessageTrackerTest.java b/zookeeper-server/src/test/java/org/apache/zookeeper/server/util/MessageTrackerTest.java
index d400cf9..9e1d6b3 100644
--- a/zookeeper-server/src/test/java/org/apache/zookeeper/server/util/MessageTrackerTest.java
+++ b/zookeeper-server/src/test/java/org/apache/zookeeper/server/util/MessageTrackerTest.java
@@ -20,6 +20,9 @@

 import static org.junit.jupiter.api.Assertions.assertEquals;
 import static org.junit.jupiter.api.Assertions.assertNull;
+import static org.junit.jupiter.api.Assertions.assertThrows;
+import static org.junit.jupiter.api.Assertions.assertTrue;
+
 import org.junit.jupiter.api.AfterEach;
 import org.junit.jupiter.api.BeforeEach;
 import org.junit.jupiter.api.Test;
@@ -127,4 +130,30 @@ public void testDumpToLog() {
         assertNull(messageTracker.peekSent());
         assertNull(messageTracker.peekReceived());
     }
+
+    @Test
+    public void testIPv6VerificationGood() {
+        MessageTracker messageTracker = new MessageTracker(10);
+        //see https://www.ibm.com/docs/en/ts4500-tape-library?topic=functionality-ipv4-ipv6-address-formats
+        for (String serverAddr : new String[] {
+                "2001:db8:3333:4444:5555:6666:7777:8888",
+                "2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF",
+                "::", "2001:db8::", "2001:db8::1234:5678",
+                "2001:0db8:0001:0000:0000:0ab9:C0A8:0102"
+        }) {
+            messageTracker.dumpToLog(serverAddr);
+        }
+    }
+
+    @Test
+    public void testIPv6TooManyColons() {
+        final String serverAddr = "2001:db8:1234:0000:0000:0000:0000:0000:0000";
+        MessageTracker messageTracker = new MessageTracker(10);
+        IllegalArgumentException thrown = assertThrows(
+                IllegalArgumentException.class,
+                () -> messageTracker.dumpToLog(serverAddr),
+                "Expected dumpToLog to throw IllegalArgumentException, but it didn't"
+        );
+        assertTrue(thrown.getMessage().contains("too many colons=1"));
+    }
 }"""
    t = tempfile.NamedTemporaryFile()
    path_t: Path = Path(t.name)
    with path_t.open(mode="wt") as f:
        f.write(content)
        f.flush()
    result: list[dict] = Delta().get_sinks(path_t)
    assert result == [
        {
            "file_path": "zookeeper-server/src/main/java/org/apache/zookeeper/server/util/MessageTracker.java",
            "line": 145,
            "v_type": "Infinite loop",
        }
    ]
