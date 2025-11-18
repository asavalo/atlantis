import tempfile
from pathlib import Path
from typing import List, Tuple

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment.exceptions import ChallengeWrongPatchError
from crete.framework.environment.functions import (
    _extract_file_paths_from_diff,  # pyright: ignore[reportPrivateUsage]
    check_valid_diff,
    check_valid_language,
    resolve_project_path,
)
from crete.framework.environment.services.oss_fuzz.default import cleanup_build_logs
from crete.framework.evaluator.services.dummy import DummyEvaluator
from pydantic import BaseModel
from python_aixcc_challenge.language.types import Language


class _TestDiff(BaseModel):
    name: str
    diff: str
    target_pair: List[Tuple[str, str]]


@pytest.fixture
def source_dir(detection_jvm_mock_java_cpv_0: tuple[Path, Path]) -> Path:
    context, _detection = AIxCCContextBuilder(
        *detection_jvm_mock_java_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )
    return context["pool"].source_directory


@pytest.mark.parametrize(
    "input_path,expected_suffix",
    [
        # Exact matching
        (
            "src/main/java/com/aixcc/mock_java/App.java",
            "src/main/java/com/aixcc/mock_java/App.java",
        ),
        # Sub_path matching
        ("com/aixcc/mock_java/App.java", "src/main/java/com/aixcc/mock_java/App.java"),
        # Sub_path matching with relative path
        (
            "/out/main/java/com/aixcc/mock_java/App.java",
            "src/main/java/com/aixcc/mock_java/App.java",
        ),
    ],
)
def test_resolve_project_path(source_dir: Path, input_path: str, expected_suffix: str):
    file = Path(input_path)
    assert resolve_project_path(file, source_dir) == source_dir / expected_suffix


def test_cleanup_build_logs():
    log = b"""
Downloaded from central: https://repo.maven.apache.org/maven2/net/nicoulaj/maven/plugins/checksum-maven-plugin/1.8/checksum-maven-plugin-1.8.pom (13 kB at 1.2 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/net/nicoulaj/parent/54/parent-54.pom
Progress (1): 16/29 kB
Progress (1): 29 kB   
                   
Downloaded from central: https://repo.maven.apache.org/maven2/net/nicoulaj/parent/54/parent-54.pom (29 kB at 2.9 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/net/nicoulaj/maven/plugins/checksum-maven-plugin/1.8/checksum-maven-plugin-1.8.jar
Progress (1): 16/69 kB
Progress (1): 33/69 kB
Progress (1): 49/69 kB
Progress (1): 66/69 kB
Progress (1): 69 kB   
                   
Downloaded from central: https://repo.maven.apache.org/maven2/net/nicoulaj/maven/plugins/checksum-maven-plugin/1.8/checksum-maven-plugin-1.8.jar (69 kB at 6.3 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-enforcer-plugin/3.0.0-M3/maven-enforcer-plugin-3.0.0-M3.pom
Progress (1): 7.3 kB
                    
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-enforcer-plugin/3.0.0-M3/maven-enforcer-plugin-3.0.0-M3.pom (7.3 kB at 815 kB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/enforcer/enforcer/3.0.0-M3/enforcer-3.0.0-M3.pom
Progress (1): 7.8 kB
                    
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/enforcer/enforcer/3.0.0-M3/enforcer-3.0.0-M3.pom (7.8 kB at 1.1 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-enforcer-plugin/3.0.0-M3/maven-enforcer-plugin-3.0.0-M3.jar
Progress (1): 16/27 kB
Progress (1): 27 kB   
                   
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-enforcer-plugin/3.0.0-M3/maven-enforcer-plugin-3.0.0-M3.jar (27 kB at 3.4 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-site-plugin/3.7.1/maven-site-plugin-3.7.1.pom
Progress (1): 16/19 kB
Progress (1): 19 kB   
                   
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-site-plugin/3.7.1/maven-site-plugin-3.7.1.pom (19 kB at 2.4 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-plugins/31/maven-plugins-31.pom
Progress (1): 10 kB
                   
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-plugins/31/maven-plugins-31.pom (10 kB at 1.2 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/maven-parent/31/maven-parent-31.pom
Progress (1): 16/43 kB
Progress (1): 33/43 kB
Progress (1): 43 kB   
                   
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/maven-parent/31/maven-parent-31.pom (43 kB at 5.4 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/apache/19/apache-19.pom
Progress (1): 15 kB
                   
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/apache/19/apache-19.pom (15 kB at 1.9 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-site-plugin/3.7.1/maven-site-plugin-3.7.1.jar
Progress (1): 16/135 kB
Progress (1): 33/135 kB
Progress (1): 49/135 kB
Progress (1): 66/135 kB
Progress (1): 82/135 kB
Progress (1): 98/135 kB
Progress (1): 115/135 kB
Progress (1): 131/135 kB
Progress (1): 135 kB    
                    
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-site-plugin/3.7.1/maven-site-plugin-3.7.1.jar (135 kB at 12 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-clean-plugin/3.1.0/maven-clean-plugin-3.1.0.pom
Progress (1): 5.2 kB
                    
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-clean-plugin/3.1.0/maven-clean-plugin-3.1.0.pom (5.2 kB at 575 kB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-clean-plugin/3.1.0/maven-clean-plugin-3.1.0.jar
Progress (1): 16/30 kB
Progress (1): 30 kB   
                   
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-clean-plugin/3.1.0/maven-clean-plugin-3.1.0.jar (30 kB at 3.4 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/com/github/koraktor/mavanagaiata/0.9.4/mavanagaiata-0.9.4.pom
Progress (1): 16/19 kB
Progress (1): 19 kB   
                   
Downloaded from central: https://repo.maven.apache.org/maven2/com/github/koraktor/mavanagaiata/0.9.4/mavanagaiata-0.9.4.pom (19 kB at 2.1 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/com/github/koraktor/mavanagaiata/0.9.4/mavanagaiata-0.9.4.jar
Progress (1): 16/75 kB
Progress (1): 33/75 kB
Progress (1): 49/75 kB
Progress (1): 66/75 kB
Progress (1): 75 kB   
                   
Downloaded from central: https://repo.maven.apache.org/maven2/com/github/koraktor/mavanagaiata/0.9.4/mavanagaiata-0.9.4.jar (75 kB at 8.3 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-antrun-plugin/1.8/maven-antrun-plugin-1.8.pom
Progress (1): 3.3 kB
                    
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-antrun-plugin/1.8/maven-antrun-plugin-1.8.pom (3.3 kB at 473 kB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-plugins/27/maven-plugins-27.pom
Progress (1): 11 kB
                   
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-plugins/27/maven-plugins-27.pom (11 kB at 1.9 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/maven-parent/26/maven-parent-26.pom
Progress (1): 16/40 kB
Progress (1): 33/40 kB
Progress (1): 40 kB   
                   
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/maven-parent/26/maven-parent-26.pom (40 kB at 4.0 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/apache/16/apache-16.pom
Progress (1): 15 kB
                   
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/apache/16/apache-16.pom (15 kB at 2.2 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-antrun-plugin/1.8/maven-antrun-plugin-1.8.jar
Progress (1): 16/36 kB
Progress (1): 33/36 kB
Progress (1): 36 kB   
                   
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-antrun-plugin/1.8/maven-antrun-plugin-1.8.jar (36 kB at 4.5 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-jar-plugin/3.2.0/maven-jar-plugin-3.2.0.pom
Progress (1): 7.3 kB
                    
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-jar-plugin/3.2.0/maven-jar-plugin-3.2.0.pom (7.3 kB at 1.0 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-jar-plugin/3.2.0/maven-jar-plugin-3.2.0.jar
Progress (1): 16/29 kB
Progress (1): 29 kB   
                   
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-jar-plugin/3.2.0/maven-jar-plugin-3.2.0.jar (29 kB at 4.1 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/cyclonedx/cyclonedx-maven-plugin/2.7.9/cyclonedx-maven-plugin-2.7.9.pom
Progress (1): 16/17 kB
Progress (1): 17 kB   
                   
Downloaded from central: https://repo.maven.apache.org/maven2/org/cyclonedx/cyclonedx-maven-plugin/2.7.9/cyclonedx-maven-plugin-2.7.9.pom (17 kB at 1.9 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/junit/junit-bom/5.9.3/junit-bom-5.9.3.pom
Progress (1): 5.6 kB
                    
Downloaded from central: https://repo.maven.apache.org/maven2/org/junit/junit-bom/5.9.3/junit-bom-5.9.3.pom (5.6 kB at 804 kB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/cyclonedx/cyclonedx-maven-plugin/2.7.9/cyclonedx-maven-plugin-2.7.9.jar
Progress (1): 16/45 kB
Progress (1): 33/45 kB
Progress (1): 45 kB   
                   
Downloaded from central: https://repo.maven.apache.org/maven2/org/cyclonedx/cyclonedx-maven-plugin/2.7.9/cyclonedx-maven-plugin-2.7.9.jar (45 kB at 4.5 MB/s)
[INFO] 
[INFO] --- clean:3.1.0:clean (default-clean) @ parent ---
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/maven-plugin-api/3.0/maven-plugin-api-3.0.pom
Progress (1): 2.3 kB
                    
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/maven-plugin-api/3.0/maven-plugin-api-3.0.pom (2.3 kB at 381 kB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/maven/3.0/maven-3.0.pom
Progress (1): 16/22 kB
Progress (1): 22 kB   
                   
Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/maven/3.0/maven-3.0.pom (22 kB at 3.1 MB/s)
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/maven-parent/15/maven-parent-15.pom
Progress (1): 16/24 kB
Progress (1): 24 kB   
                   
    """
    cleaned_up = cleanup_build_logs(log).strip()
    expected = b"[INFO] \n[INFO] --- clean:3.1.0:clean (default-clean) @ parent ---"
    assert cleaned_up == expected


# Sample diff data in git format
sample_diff_git = _TestDiff(
    name="Git format diff (multiple files)",
    diff="""diff --git a/src/main.c b/src/main.c
index 1234567..abcdefg 100644
--- a/src/main.c
+++ b/src/main.c
@@ -10,3 +10,3 @@ int main() {
     printf("Hello World\\n");
-    return 0;
+    return 1;
 }

diff --git a/include/header.h b/include/header.h
index 9876543..fedcba9 100644
--- a/include/header.h
+++ b/include/header.h
@@ -1,3 +1,4 @@
 #ifndef HEADER_H
 #define HEADER_H
+#include <stdio.h>
 #endif
""",
    target_pair=[
        ("src/main.c", "src/main.c"),
        ("include/header.h", "include/header.h"),
    ],
)

# Sample diff data in simple format
sample_diff_simple = _TestDiff(
    name="Simple format diff",
    diff="""--- old_file.c
+++ new_file.c
@@ -1,3 +1,3 @@
     printf("Hello World\\n");
-    return 0;
+    return 1;
 }
""",
    target_pair=[("old_file.c", "new_file.c")],
)

# Sample diff with /dev/null (new file)
sample_diff_new_file = _TestDiff(
    name="New file diff",
    diff="""--- /dev/null
+++ b/new_file.c
@@ -0,0 +1,3 @@
+int hello() {
+    printf("Hello, World!");
+    return 0;
""",
    target_pair=[("/dev/null", "new_file.c")],
)

# Sample diff with file deletion
sample_diff_delete_file = _TestDiff(
    name="Delete file diff",
    diff="""--- a/old_file.c
+++ /dev/null
@@ -1,3 +0,0 @@
-// line 1
-// line 2
-// line 3
""",
    target_pair=[("old_file.c", "/dev/null")],
)

# Sample diff with complex paths
sample_diff_complex = _TestDiff(
    name="Complex multi-file diff",
    diff="""diff --git a/src/utils/helper.c b/src/utils/helper.c
index abc123..def456 100644
--- a/src/utils/helper.c
+++ b/src/utils/helper.c
@@ -1,5 +1,6 @@
 #include <stdio.h>
 #include <stdlib.h>
+#include <string.h>

 void helper_function(){
 }

diff --git a/tests/test_main.c b/tests/test_main.c
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/tests/test_main.c
@@ -0,0 +1,10 @@
+#include <stdio.h>
+#include <string.h>
+
+int main() {
+    printf("Hello, World!");
+    printf("Hello, World!");
+    printf("Hello, World!");
+    printf("Hello, World!");
+    return 0;
+ }
""",
    target_pair=[
        ("src/utils/helper.c", "src/utils/helper.c"),
        ("/dev/null", "tests/test_main.c"),
    ],
)

# Real-world example from OSS-Fuzz projects
sample_diff_real = _TestDiff(
    name="Real-world OSS-Fuzz diff",
    diff="""diff --git a/src/jv.c b/src/jv.c
index e23d8ec..6ca1e1d 100644
--- a/src/jv.c
+++ b/src/jv.c
@@ -635,7 +635,7 @@ static const char* jvp_literal_number_literal(jv n) {
   }
 
   if (plit->literal_data == NULL) {
-    int len = jvp_dec_number_ptr(n)->digits + 15 /* 14 + NUL */;
+    int len = jvp_dec_number_ptr(n)->digits + 14;
     plit->literal_data = jv_mem_alloc(len);
 
     // Preserve the actual precision as we have parsed it

""",
    target_pair=[("src/jv.c", "src/jv.c")],
)

# Sample diff with binary file (should be handled gracefully)
sample_diff_binary = _TestDiff(
    name="Binary file diff",
    diff="""diff --git a/image.png b/image.png
index 1234567..abcdefg 100644
Binary files a/image.png and b/image.png differ
""",
    target_pair=[("image.png", "image.png")],
)


sample_no_newline = _TestDiff(
    name="No newline at end of file",
    diff=r"""diff --git a/vuln.c b/vuln.c
index 15206dc..df29443 100644
--- a/vuln.c
+++ b/vuln.c
@@ -26,7 +26,8 @@ bool person_info_parse_file(person_info_t * person_info, const char * const in)
     for (; isspace(in[last_pos]); last_pos++);
 
     // The bug is THE LINE BELOW THIS LINE
-    strcpy(person_info->name, &in[last_pos]);
+    strncpy(person_info->name, &in[last_pos], MAX_STRLEN-1);
+    person_info->name[MAX_STRLEN-1] = '\0';
 
     return true;
-}
\ No newline at end of file
+}
""",
    target_pair=[("vuln.c", "vuln.c")],
)


# Sample diff with fuzzer file
sample_diff_fuzzer = _TestDiff(
    name="Fuzzer file diff",
    diff="""diff --git a/fuzz/fuzz.c b/fuzz/fuzz.c
index 1234567..abcdefg 100644
--- a/fuzz/fuzz.c
@@ -1,3 +1,3 @@
 #include <stdio.h>
-int main() {
+int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
     return 0;
 }
""",
    target_pair=[("fuzz/fuzz.c", "fuzz/fuzz.c")],
)

sample_diff_fuzzer_by_name = _TestDiff(
    name="Fuzzer file diff by name",
    diff="""diff --git a/fuzz/harness.c b/fuzz/harness.c
index 1234567..abcdefg 100644
--- a/fuzz/harness.c
@@ -1,3 +1,3 @@
 #include <stdio.h>
-int main() {
+int no_fuzzer_function(const uint8_t* data, size_t size) {
     return 0;
 }
""",
    target_pair=[("fuzz/harness.c", "fuzz/harness.c")],
)

sample_diff_fuzzer_by_content = _TestDiff(
    name="Fuzzer file diff by content",
    diff="""diff --git a/utils/wrapper.c b/utils/wrapper.c
index 1234567..abcdefg 100644
--- a/utils/wrapper.c
@@ -1,3 +1,3 @@
 #include <stdio.h>
-int main() {
+int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
     return 0;
 }
""",
    target_pair=[("utils/wrapper.c", "utils/wrapper.c")],
)

sample_diff_regression_1406 = _TestDiff(
    name="Regression 1406",
    diff="""--- a/bfd/format.c
+++ b/bfd/format.c
@@ -180,7 +180,7 @@
 
     if (abfd->iostream != preserve->iostream)
 	 {                                                                                                                                                                                            
-        if ((abfd->flags & BFD_IN_MEMORY) != 0)
+        if ((preserve->flags & BFD_IN_MEMORY) != 0)
             free (abfd->iostream);
        abfd->iostream = preserve->iostream;
     }
""",
    target_pair=[("bfd/format.c", "bfd/format.c")],
)
sample_diff_java_fuzzer = _TestDiff(
    name="Java fuzzer file diff",
    diff="""diff --git a/src/main/java/com/aixcc/mock_java/App.java b/src/main/java/com/aixcc/mock_java/App.java
index 1234567..abcdefg 100644
--- a/src/main/java/com/aixcc/mock_java/App.java
+++ b/src/main/java/com/aixcc/mock_java/App.java
@@ -1,2 +1,5 @@
 public class DataTreeFuzzer {
+    public static void fuzzerTestOneInput(const uint8_t* data, size_t size) {
+        return 0;
+    }
 }
""",
    target_pair=[
        (
            "src/main/java/com/aixcc/mock_java/App.java",
            "src/main/java/com/aixcc/mock_java/App.java",
        )
    ],
)


@pytest.mark.parametrize(
    "diff_data",
    [
        sample_diff_git,
        sample_diff_simple,
        sample_diff_new_file,
        sample_diff_delete_file,
        sample_diff_complex,
        sample_diff_real,
        sample_diff_binary,
        sample_no_newline,
        sample_diff_fuzzer,
        sample_diff_fuzzer_by_name,
        sample_diff_fuzzer_by_content,
        sample_diff_regression_1406,
        sample_diff_java_fuzzer,
    ],
)
def test_diff_parsing_success(diff_data: _TestDiff):
    paths = _extract_file_paths_from_diff(diff_data.diff)  # pyright: ignore[reportPrivateUsage]
    target_paths = [
        p for pair in diff_data.target_pair for p in pair if p != "/dev/null"
    ]
    assert set(paths) == set(Path(p) for p in target_paths)


@pytest.mark.parametrize(
    "diff_data, expected_success",
    [
        (sample_diff_git, True),
        (sample_diff_simple, True),
        (sample_diff_new_file, True),
        (sample_diff_delete_file, True),
        (sample_diff_complex, True),
        (sample_diff_real, True),
        (sample_no_newline, True),
        (sample_diff_regression_1406, True),
        (sample_diff_binary, False),
        (sample_diff_fuzzer, False),
        (sample_diff_fuzzer_by_name, False),
        (sample_diff_fuzzer_by_content, False),
        (sample_diff_java_fuzzer, False),
    ],
)
def test_check_valid_diff(
    diff_data: _TestDiff, expected_success: bool, tmpdir_as_path: Path
):
    source_directory = tmpdir_as_path

    for target_path in diff_data.target_pair:
        (source_directory / target_path[0]).parent.mkdir(parents=True, exist_ok=True)
        (source_directory / target_path[1]).parent.mkdir(parents=True, exist_ok=True)
        (source_directory / target_path[0]).write_text(
            diff_data.diff
        )  # Not a real code
        (source_directory / target_path[1]).write_text(
            diff_data.diff
        )  # Not a real code

    if expected_success:
        check_valid_diff(diff_data.diff, source_directory, "c")
    else:
        with pytest.raises(ChallengeWrongPatchError):
            check_valid_diff(diff_data.diff, source_directory, "c")


java_sample = """
public class Main {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
"""

c_sample = """
#include <stdio.h>

int main() {
    printf("Hello, World!");
}
"""


def run_check_valid_language(content: str, extension: str, language: Language) -> bool:
    with tempfile.NamedTemporaryFile(suffix=f".{extension}") as temp_file:
        temp_file.write(content.encode())
        temp_file.flush()
        return check_valid_language(Path(temp_file.name), language)


def test_check_valid_language_jvm_true():
    assert run_check_valid_language(
        content=java_sample, extension="java", language="jvm"
    )


def test_check_valid_language_jvm_false():
    assert not run_check_valid_language(
        content=java_sample, extension="class", language="jvm"
    )


def test_check_valid_language_c_true():
    assert run_check_valid_language(content=c_sample, extension="c", language="c")

    assert run_check_valid_language(content=c_sample, extension="cpp", language="c++")

    assert run_check_valid_language(
        content=java_sample, extension="c.in", language="c++"
    )


def test_check_valid_language_c_false():
    assert not run_check_valid_language(
        content=c_sample, extension="conf", language="c++"
    )

    assert not run_check_valid_language(
        content=c_sample, extension="c.ini", language="c++"
    )
