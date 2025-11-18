import os
from abc import ABC, abstractmethod

from crete.framework.agent.services.multi_retrieval.states.patch_state import (
    CodeSnippet,
)


class BasePatchExtractor(ABC):
    @abstractmethod
    def extract_patch_from_content(self, repo_path: str, content: str) -> CodeSnippet:
        pass

    def extract_code_from_markdown(self, markdown_code: str) -> str:
        stripped_code = markdown_code.strip()
        if stripped_code.startswith("```") and stripped_code.endswith("```"):
            markdown_code = stripped_code.split("\n", maxsplit=1)[1][:-3]
        else:
            if markdown_code.startswith("\n"):
                markdown_code = markdown_code[1:]
            if markdown_code.endswith("\n"):
                markdown_code = markdown_code[:-1]
        return markdown_code

    def rebase_file_path(self, repo_path: str, relative_file_path: str) -> str | None:
        # This searches a file where repo_path and issue log's file path have different base paths.
        relative_file_paths = relative_file_path.split(os.path.sep)
        rebased_file_path = None
        for i in range(len(relative_file_paths)):
            curr_path = os.path.join(*relative_file_paths[i:])
            check_path = os.path.join(repo_path, curr_path)
            if os.path.exists(check_path) and os.path.isfile(check_path):
                rebased_file_path = curr_path
                break
        return rebased_file_path
