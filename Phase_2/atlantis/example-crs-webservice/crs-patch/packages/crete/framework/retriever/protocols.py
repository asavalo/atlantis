from typing import Protocol

from haystack import Document

from crete.atoms.detection import Detection
from crete.framework.retriever.contexts import RetrievalContext


class RetrieverProtocol(Protocol):
    def retrieve(
        self, context: RetrievalContext, detection: Detection, text: str
    ) -> list[Document]: ...
