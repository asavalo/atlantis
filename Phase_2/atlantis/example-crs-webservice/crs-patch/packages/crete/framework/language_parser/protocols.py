from pathlib import Path
from typing import List, Protocol

from python_aixcc_challenge.language.types import Language

from crete.framework.language_parser.contexts import LanguageParserContext
from crete.framework.language_parser.models import LanguageNode


class LanguageParserProtocol(Protocol):
    language: Language

    def get_declarations_in_file(
        self,
        context: LanguageParserContext,
        file: Path,
    ) -> List[tuple[str, LanguageNode]]: ...

    def get_blocks_in_file(
        self, context: LanguageParserContext, file: Path
    ) -> List[LanguageNode]: ...

    def get_identifier_of_declaration(
        self,
        context: LanguageParserContext,
        file: Path,
        node: LanguageNode,
    ) -> LanguageNode | None: ...

    def get_type_string_of_declaration(
        self,
        context: LanguageParserContext,
        file: Path,
        node: LanguageNode,
    ) -> str | None: ...
