import inspect
from unittest.mock import patch

import pytest
from crete.framework.agent.services.multi_retrieval.nodes.patchers.base_patch_extractor import (
    BasePatchExtractor,
)
from crete.framework.agent.services.multi_retrieval.states.patch_state import (
    CodeSnippet,
)


@pytest.fixture
def base_patch_extractor() -> BasePatchExtractor:
    class TestBasePatchExtractor(BasePatchExtractor):
        def extract_patch_from_content(
            self, repo_path: str, content: str
        ) -> CodeSnippet:
            raise NotImplementedError

    mock_base_patch_extractor = TestBasePatchExtractor()
    return mock_base_patch_extractor


def test_extract_code_from_markdown(base_patch_extractor: BasePatchExtractor) -> None:
    markdown_content = "\ncode line 1\ncode line 2\ncode line 3\n\n"
    code = base_patch_extractor.extract_code_from_markdown(markdown_content)
    assert code == "code line 1\ncode line 2\ncode line 3\n"

    markdown_content = inspect.cleandoc(
        """\
        ```python
        code line 1
        code line 2
        code line 3
        ```
        """
    )
    code = base_patch_extractor.extract_code_from_markdown(markdown_content)
    assert code == "code line 1\ncode line 2\ncode line 3\n"

    markdown_content = inspect.cleandoc(
        """\
        ```c
        int add(int a, int b) {
            return a + b;
        }
        ```
        """
    )
    code = base_patch_extractor.extract_code_from_markdown(markdown_content)
    assert (
        code
        == """\
int add(int a, int b) {
    return a + b;
}
"""
    )

    markdown_content = inspect.cleandoc(
        """\
        ```java
            public static void main(String[] args) {
                System.out.println("Hello World");
            }
        ```
        """
    )
    code = base_patch_extractor.extract_code_from_markdown(markdown_content)
    assert (
        code
        == """\
    public static void main(String[] args) {
        System.out.println("Hello World");
    }
"""
    )

    markdown_content = """    
```c
int add(int a, int b) {
    return a + b;
}
```
    """
    code = base_patch_extractor.extract_code_from_markdown(markdown_content)
    assert (
        code
        == """\
int add(int a, int b) {
    return a + b;
}
"""
    )


def test_rebase_file_path(base_patch_extractor: BasePatchExtractor):
    repo_path = "/path/to/repo"
    relative_file_path = "valid/path/to/subdir/test.py"
    absolute_file_path = "/path/to/repo/valid/path/to/subdir/test.py"

    def exists(path: str) -> bool:
        return path == absolute_file_path

    with (
        patch("os.path.exists", exists),
        patch("os.path.isfile", exists),
    ):
        test_file_path = "valid/path/to/subdir/test.py"
        result = base_patch_extractor.rebase_file_path(repo_path, test_file_path)
        assert result == relative_file_path

        test_file_path = "invalid/path/to/subdir/test.py"
        result = base_patch_extractor.rebase_file_path(repo_path, test_file_path)
        assert result is None

        test_file_path = "rebaseable/valid/path/to/subdir/test.py"
        result = base_patch_extractor.rebase_file_path(repo_path, test_file_path)
        assert result == relative_file_path

        test_file_path = "another/rebaseable/valid/path/to/subdir/test.py"
        result = base_patch_extractor.rebase_file_path(repo_path, test_file_path)
        assert result == relative_file_path
