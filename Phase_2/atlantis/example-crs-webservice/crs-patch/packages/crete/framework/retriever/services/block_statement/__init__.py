from pathlib import Path

import litellm
from haystack import Document
from haystack.components.embedders import OpenAIDocumentEmbedder
from haystack.utils import Secret
from haystack_integrations.document_stores.qdrant import QdrantDocumentStore
from joblib import (
    Parallel,  # pyright: ignore[reportUnknownVariableType]
    delayed,  # pyright: ignore[reportUnknownVariableType]
)
from litellm.types.utils import Choices, Message, ModelResponse
from python_aixcc_challenge.language.functions import get_language_file_extensions

from crete.atoms.detection import Detection
from crete.atoms.path import DEFAULT_CACHE_DIRECTORY
from crete.framework.language_parser.models import LanguageNode
from crete.framework.retriever.contexts import RetrievalContext
from crete.framework.retriever.protocols import RetrieverProtocol

from .functions import query


class BlockStatementRetriever(RetrieverProtocol):
    def __init__(
        self,
        top_k: int,
        api_key: str,
        base_url: str,
        model: str = "gpt-4o",  # for conditional prompting
        max_lines_per_block: int = 10,
        similarity_min_threshold: float = 0.5,
    ):
        self._top_k = top_k
        self._api_key = api_key
        self._base_url = base_url
        self._model = model
        self._max_lines_per_block = max_lines_per_block
        self._similarity_min_threshold = similarity_min_threshold

    def retrieve(
        self, context: RetrievalContext, detection: Detection, text: str
    ) -> list[Document]:
        documents_directory = self._get_documents_directory(
            context, detection, context["pool"].source_directory
        )
        context["logger"].info(f" [+] Using documents from {documents_directory}")

        documents = [
            document
            for document in query(
                {
                    "api_key": self._api_key,
                    "base_url": self._base_url,
                    "top_k": self._top_k + 1,  # Include the original code
                },
                text,
                documents_directory=documents_directory,
            )
            if document.content is not None and document.content != text
        ]
        assert len(documents) > 0, "No documents retrieved"

        documents = self._filter_with_score_min_threshold(documents)
        if len(documents) == 0:
            context["logger"].info("No documents passed the similarity threshold.")
            return []

        if not self._same_purpose_codes_with_different_patterns(text, documents):
            context["logger"].info("Not worth to try.")
            return []

        return documents

    def _get_documents_directory(
        self, context: RetrievalContext, detection: Detection, source_directory: Path
    ) -> Path:
        documents_directory = (
            DEFAULT_CACHE_DIRECTORY
            / "block_statement_documents"
            / _sanitize_filename(detection.project_name)
        )
        if documents_directory.exists():
            return documents_directory

        return self._generate_documents_directory(
            context, detection, documents_directory, source_directory
        )

    def _generate_documents_directory(
        self,
        context: RetrievalContext,
        detection: Detection,
        documents_directory: Path,
        source_directory: Path,
    ) -> Path:
        documents = self._generate_documents(context, detection, source_directory)

        # TODO: Filter out max token length

        document_embedder = OpenAIDocumentEmbedder(
            api_key=Secret.from_token(self._api_key),
            api_base_url=self._base_url,
            model="text-embedding-3-large",  # Intended to be hardcoded to match with generator
        )

        documents_with_embedding = document_embedder.run(documents)["documents"]

        document_store = QdrantDocumentStore(
            path=str(documents_directory),
            index="Document",
            recreate_index=True,
            embedding_dim=3072,
        )

        document_store.write_documents(
            documents_with_embedding  # pyright: ignore[reportArgumentType]
        )

        return documents_directory

    def _generate_documents(
        self, context: RetrievalContext, detection: Detection, source_directory: Path
    ) -> list[Document]:
        file_extensions = get_language_file_extensions(detection.language)
        files = [p for p in source_directory.rglob("*") if p.suffix in file_extensions]
        blocks = [
            block
            for file in files
            for block in context["language_parser"].get_blocks_in_file(context, file)
            if block.end_line - block.start_line <= self._max_lines_per_block
        ]
        context["logger"].info(f" [+] Found {len(blocks)} target blocks")
        return list(
            Parallel(n_jobs=-1)(
                delayed(_as_document)(context, block) for block in blocks
            )
        )

    def _filter_with_score_min_threshold(
        self, documents: list[Document]
    ) -> list[Document]:
        return [
            document
            for document in documents
            if document.score and document.score > self._similarity_min_threshold
        ]

    def _same_purpose_codes_with_different_patterns(
        self, text: str, documents: list[Document]
    ) -> bool:
        prompt = f"""Comparing the following target code block with the reference code blocks,
is there any mistake in the target code block that is not present in the reference code blocks?
Answer with 'yes' or 'no' and provide a brief explanation.

Target block:

{text}

Reference code blocks:

{"\n".join([document.content for document in documents if document.content])}
    """

        response = litellm.completion(  # pyright: ignore[reportUnknownMemberType]
            api_key=self._api_key,
            base_url=self._base_url,
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
        )
        assert isinstance(response, ModelResponse), "Unreachable code"
        assert isinstance(response.choices[0], Choices), "Failed to get choices."
        assert isinstance(response.choices[0].message, Message), (
            "Failed to get message."
        )

        response_message = response.choices[0].message.content
        if not response_message:
            return False

        return "yes" in response_message.lower()


def _sanitize_filename(filename: str) -> str:
    return filename.replace("/", "_").replace("\\", "_")


def _as_document(context: RetrievalContext, block: LanguageNode) -> Document:
    return Document(
        content=block.text,
        meta={
            "file": Path(block.file).relative_to(context["pool"].source_directory),
            "start_line": block.start_line,
            "start_column": block.start_column,
            "end_line": block.end_line,
            "end_column": block.end_column,
        },
    )
