from pathlib import Path
import numpy as np
from pydantic import BaseModel
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.vincent.nodes.requests.functions import (
    aggregate_code_query_results,
)
from crete.framework.agent.services.vincent.code_inspector.functions import (
    append_line_num,
)
from crete.framework.agent.services.vincent.nodes.requests.handlers.base_request_handler import (
    BaseRequestHandler,
)
from crete.framework.agent.services.vincent.functions import (
    LLMRequest,
)
from crete.framework.agent.services.vincent.code_inspector.models import (
    CodeQueryResult,
    CodeSnippet,
)

from crete.framework.agent.services.vincent.code_inspector import (
    VincentCodeInspector,
)
from langchain_openai import OpenAIEmbeddings
from python_llm.api.actors import LlmApiManager
import openai

DEFAULT_RESULT_COUNT_PER_SRC = 5


def _cosine_similarity(vec1: list[float], vec2: list[float]) -> float:
    vec1_arr = np.array(vec1)
    vec2_arr = np.array(vec2)
    # avoid floating-point precision errors by using min/max
    return min(
        1.0,
        max(
            -1.0,
            np.dot(vec1_arr, vec2_arr)
            / (np.linalg.norm(vec1_arr) * np.linalg.norm(vec2_arr)),
        ),
    )


class SnippetEmbedCache(BaseModel):
    snippet_hash: int
    query_result: CodeQueryResult
    embed: list[float]


class SimilarCodeRequestHandler(BaseRequestHandler):
    # @TODO: embedding cache using filesystem will be introduced
    def __init__(
        self,
        context: AgentContext,
        code_inspector: VincentCodeInspector,
        llm_api_manager: LlmApiManager,
        result_count: int = DEFAULT_RESULT_COUNT_PER_SRC,
    ):
        super().__init__(context)
        self.code_inspector = code_inspector
        self.embed_cache: dict[int, SnippetEmbedCache] = {}
        self.visited_srcs: set[Path] = set()

        self.embeddings = OpenAIEmbeddings(
            model="text-embedding-3-large",
            openai_api_base=llm_api_manager.base_url,  # pyright: ignore[reportCallIssue]
            openai_api_key=llm_api_manager.api_key,  # pyright: ignore[reportCallIssue]
            # openai_api_base=os.environ["LITELLM_API_BASE"],  # pyright: ignore[reportCallIssue]
            # openai_api_key=os.environ["LITELLM_API_KEY"],  # pyright: ignore[reportCallIssue]
        )

        self.count = result_count

    def get_embedding_from_query_result(
        self, query_result: CodeQueryResult
    ) -> list[float]:
        try:
            return self.embed_cache[hash(query_result.snippet.text)].embed
        except KeyError:
            snippet_hash = hash(query_result.snippet.text)
            self.embed_cache[snippet_hash] = SnippetEmbedCache(
                snippet_hash=snippet_hash,
                query_result=query_result,
                embed=self.embeddings.embed_query(query_result.snippet.text),
            )
            return self.embed_cache[snippet_hash].embed

    def embed_functions_in_source(self, abs_src_path: Path):
        self.context["logger"].info(f'create embeddings for "{str(abs_src_path)}"')
        for entry in self.code_inspector.get_all_functions_in_source(abs_src_path):
            query_results_without_lines = self.code_inspector.get_definition(
                entry.name, print_line=False
            )

            if query_results_without_lines is None:
                continue

            query_result = next(
                query_result
                for query_result in query_results_without_lines
                if query_result.abs_src_path == abs_src_path
            )

            self.get_embedding_from_query_result(query_result)

        self.visited_srcs.add(abs_src_path)

    def _get_N_similar_functions(
        self, target: CodeQueryResult, N: int = 5
    ) -> list[CodeQueryResult]:
        target_embed = self.get_embedding_from_query_result(target)

        rank_with_similarity = sorted(
            [
                (
                    snippet_embed_cache,
                    _cosine_similarity(snippet_embed_cache.embed, target_embed),
                )
                for snippet_embed_cache in self.embed_cache.values()
            ],
            key=lambda x: x[1],
            reverse=True,
        )

        return [
            embed_tuple[0].query_result
            for embed_tuple in rank_with_similarity
            if embed_tuple[1] != 1.0
        ][:N]

    def handle_request(self, request: LLMRequest) -> str:
        assert request.targets is not None

        if len(request.targets) > 1:
            return f'Your request "{request.raw}" has more than one target function. Please include only one target function for each similar type of request.\n'

        if len(request.targets) == 0:
            # LLM requested with invalid format.
            return f'Your request "{request.raw}" seems not to follow the request rule. Check again your request.\n\n'

        target_name = request.targets[0]

        target_query_results = self.code_inspector.get_definition(
            target_name, print_line=False
        )

        if target_query_results is None:
            return f'Your request "{request.raw}" cannot be resolved because `{target_name}` was not found in the project codebase.\n'

        for abs_src_path in self.code_inspector.get_visited_src_list():
            if abs_src_path in self.visited_srcs:
                continue

            try:
                self.embed_functions_in_source(abs_src_path)
            except (
                openai.InternalServerError,
                openai.AuthenticationError,
                openai.RateLimitError,
                openai.APIConnectionError,
            ):
                return f'Your request "{request.raw}" cannot be resolved because an internal system error occurred during the information retrieval. Avoid requesting "similar" type requests from now.\n'

        result_info_txt = ""
        for query_result in target_query_results:
            result_info_txt += (
                f"Here are some functions that appear similar to `{target_name}`:\n\n"
            )

            try:
                result_info_txt = aggregate_code_query_results(
                    result_info_txt,
                    _append_line_nums_to_query_results(
                        self._get_N_similar_functions(query_result)
                    ),
                )
            except (
                openai.InternalServerError
                and openai.AuthenticationError
                and openai.RateLimitError
                and openai.APIConnectionError
            ):
                return f'Your request "{request.raw}" cannot be resolved because an internal system error occurred during the information retrieval. Avoid requesting "similar" type requests from now.\n'

        return result_info_txt


def _append_line_nums_to_query_results(
    query_results: list[CodeQueryResult],
) -> list[CodeQueryResult]:
    return [
        CodeQueryResult(
            abs_src_path=result.abs_src_path,
            src_path=result.src_path,
            snippet=CodeSnippet(
                start_line=result.snippet.start_line,
                end_line=result.snippet.end_line,
                text=append_line_num(result.snippet.text, result.snippet.start_line),
            ),
            is_tree_sitter=result.is_tree_sitter,
        )
        for result in query_results
    ]
