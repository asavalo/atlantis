from pathlib import Path
from typing import TypedDict, cast

from haystack.components.embedders import OpenAITextEmbedder
from haystack.utils import Secret
from haystack_integrations.components.retrievers.qdrant import QdrantEmbeddingRetriever
from haystack_integrations.document_stores.qdrant import QdrantDocumentStore


class QueryContext(TypedDict):
    api_key: str
    base_url: str
    top_k: int | None


def query(
    context: QueryContext,
    text: str,
    documents_directory: Path,
):
    query_embedder = OpenAITextEmbedder(
        api_key=Secret.from_token(context["api_key"]),
        api_base_url=context["base_url"],
        model="text-embedding-3-large",  # Intended to be hardcoded to match with generator
    )

    document_store = QdrantDocumentStore(
        path=str(documents_directory),
        index="Document",
        embedding_dim=3072,  # Intended to be hardcoded to match with generator
    )

    retriever = QdrantEmbeddingRetriever(document_store=document_store)

    query = cast(list[float], query_embedder.run(text)["embedding"])
    documents = retriever.run(query, top_k=context["top_k"])["documents"]

    document_store.client.close()

    return documents
