from haystack import Document

from crete.atoms.detection import Detection
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.insighter.protocols import InsighterProtocol
from crete.framework.language_parser.models import LanguageNode


class SimilarCodeInsighter(InsighterProtocol):
    def __init__(self, block: LanguageNode, documents: list[Document]):
        self._block = block
        self._documents = documents

    def create(self, context: InsighterContext, detection: Detection) -> str | None:
        insight = (
            "You should fix the vulnerability by replacing the following code:\n\n"
        )
        insight += "%s:%d-%d\n\n" % (
            self._block.file.relative_to(context["pool"].source_directory),
            self._block.start_line + 1,
            self._block.end_line,
        )
        insight += f"{self._block.text}\n\n"
        insight += "Refer to the below similar code to fix the vulnerability:\n"
        for document in self._documents:
            location = "%s:%d-%d" % (
                document.meta["file"],
                document.meta["start_line"] + 1,
                document.meta["end_line"],
            )
            insight += f"\n{location}\n{document.content}\n"
        return insight
