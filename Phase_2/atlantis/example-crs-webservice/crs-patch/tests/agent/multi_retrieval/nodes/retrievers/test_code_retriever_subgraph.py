import inspect
import os
import tempfile

import pytest
from crete.framework.agent.services.multi_retrieval.nodes.retrievers.code_retriever_subgraph import (
    CodeRetrieverSubgraph,
)


@pytest.fixture
def code_retriever():
    mock_code_retriever = CodeRetrieverSubgraph(
        max_retrievals_per_query=8, add_line_numbers=True
    )
    return mock_code_retriever


def test_retrieve_from_content(code_retriever: CodeRetrieverSubgraph):
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_path = temp_dir
        temp_file1 = os.path.join(temp_dir, "temp1.c")
        temp_file2 = os.path.join(temp_dir, "temp2.c")
        test_function1 = "int test1() {\n    return 1;\n}\n"
        test_function2 = "int test2() {\n    return 2;\n}\n"
        with open(temp_file1, "w", encoding="utf-8") as f:
            f.write(test_function1)
        with open(temp_file2, "w", encoding="utf-8") as f:
            f.write(test_function2)

        content_file = inspect.cleandoc(
            """
            <file>temp1.c</file>
            <file>temp2.c</file>
            """
        )
        retrieved_code = code_retriever.retrieve_from_content(content_file, repo_path)
        assert (
            retrieved_code
            == """\
<retrieved>
temp1.c
<code>
temp1.c:1-3
```
1:int test1() {
2:    return 1;
3:}
```
</code>
</retrieved>
<retrieved>
temp2.c
<code>
temp2.c:1-3
```
1:int test2() {
2:    return 2;
3:}
```
</code>
</retrieved>"""
        )

        content_file_with_lines = inspect.cleandoc(
            """
            <file>temp1.c:1-3</file>
            <file>temp1.c:2-3</file>
            """
        )
        retrieved_code = code_retriever.retrieve_from_content(
            content_file_with_lines, repo_path
        )
        assert (
            retrieved_code
            == """\
<retrieved>
temp1.c:1-3
<code>
temp1.c:1-3
```
1:int test1() {
2:    return 1;
3:}
```
</code>
</retrieved>
<retrieved>
temp1.c:2-3
<code>
temp1.c:2-3
```
2:    return 1;
3:}
```
</code>
</retrieved>"""
        )

        content_grep = inspect.cleandoc(
            """
            <grep>test1</grep>
            <grep>test2</grep>
            """
        )
        retrieved_code = code_retriever.retrieve_from_content(content_grep, repo_path)
        assert (
            retrieved_code
            == """\
<retrieved>
test1
<code>
temp1.c:1-3
```c
1:int test1() {
2:    return 1;
3:}
```
</code>
</retrieved>
<retrieved>
test2
<code>
temp2.c:1-3
```c
1:int test2() {
2:    return 2;
3:}
```
</code>
</retrieved>"""
        )

        content_mixed = inspect.cleandoc(
            """
            <file>temp1.c</file>
            <grep>test2</grep>
            """
        )
        retrieved_code = code_retriever.retrieve_from_content(content_mixed, repo_path)
        assert (
            retrieved_code
            == """\
<retrieved>
test2
<code>
temp2.c:1-3
```c
1:int test2() {
2:    return 2;
3:}
```
</code>
</retrieved>
<retrieved>
temp1.c
<code>
temp1.c:1-3
```
1:int test1() {
2:    return 1;
3:}
```
</code>
</retrieved>"""
        )
