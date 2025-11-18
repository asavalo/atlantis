from pathlib import Path

import pylspclient
import pylspclient.lsp_pydantic_strcuts as lsp
from crete.commons.logging.hooks import use_logger
from pylspclient.lsp_pydantic_strcuts import (
    LanguageIdentifier,
    ReferenceContext,
    TextDocumentIdentifier,
    TextDocumentItem,
)
from python_aixcc_challenge.language.types import Language

from .functions import (
    start_language_server,
    start_language_server_session,
    workdir_of_project,
)
from .models import Location, SymbolInformation

logger = use_logger()


class LspClient:
    def __init__(self, project_name: str, language: Language, source_directory: Path):
        self._project_name = project_name
        self._source_directory: Path = source_directory
        self._language: Language = language
        self._client: pylspclient.LspClient | None = None
        self._initialization_attempted = False

        self._language_id = self._language_to_language_id(language)
        self._source_directory_in_docker = workdir_of_project(project_name)

    @property
    def client(self) -> pylspclient.LspClient | None:
        # This is for lazy initialization
        if self._client is None and not self._initialization_attempted:
            self._initialization_attempted = True
            self._client = self._initialize()

        return self._client

    def _initialize(self) -> pylspclient.LspClient | None:
        if not start_language_server(self._project_name, self._source_directory):
            return None

        return start_language_server_session(self._project_name, self._language)

    def _open(self, file: Path) -> bool:
        if not file.is_absolute():
            file = self._source_directory / file
        logger.debug(f"[LSP request] open: {file}")
        if self.client is None:
            logger.warning("LSP client is not initialized")
            return False
        try:
            self.client.didOpen(
                TextDocumentItem(
                    uri=self._to_docker_uri(file),
                    languageId=self._language_id,
                    version=1,
                    text=file.read_text(errors="replace"),
                )
            )
        except TimeoutError:
            logger.warning("LSP client timed out")
            return False

        logger.debug(f"[LSP response] open: {file}")
        return True

    def goto_definitions(self, file: Path, line: int, column: int) -> list[Location]:
        if self.client is None:
            logger.warning("LSP client is not initialized")
            return []
        self._open(file)
        logger.debug(f"[LSP request] goto definitions: {file}:{line}:{column}")

        try:
            locations = self.client.definition(
                TextDocumentIdentifier(uri=self._to_docker_uri(file)),
                lsp.Position(line=line, character=column),
            )
        except TimeoutError:
            logger.warning("LSP client timed out")
            return []

        logger.debug(f"[LSP response] goto definitions: {locations}")
        return self._normalize_locations(locations)

    def goto_type_definitions(
        self, file: Path, line: int, column: int
    ) -> list[Location]:
        if self.client is None:
            logger.warning("LSP client is not initialized")
            return []
        self._open(file)
        logger.debug(f"[LSP request] goto type definitions: {file}:{line}:{column}")

        try:
            locations = self.client.typeDefinition(
                TextDocumentIdentifier(uri=self._to_docker_uri(file)),
                lsp.Position(line=line, character=column),
            )
        except TimeoutError:
            logger.warning("LSP client timed out")
            return []

        logger.debug(f"[LSP response] goto type definitions: {locations}")
        return self._normalize_locations(locations)

    def document_symbol(self, file: Path) -> list[SymbolInformation]:
        if self.client is None:
            logger.warning("LSP client is not initialized")
            return []
        self._open(file)
        logger.debug(f"[LSP request] goto document symbols: {file}")

        try:
            symbols = self.client.documentSymbol(
                TextDocumentIdentifier(uri=self._to_docker_uri(file))
            )
        except TimeoutError:
            logger.warning("LSP client timed out")
            return []

        logger.debug(f"[LSP response] goto document symbols: {symbols}")  # pyright: ignore
        return self._normalize_symbols(symbols)  # pyright: ignore

    def goto_references(self, file: Path, line: int, column: int) -> list[Location]:
        if self.client is None:
            logger.warning("LSP client is not initialized")
            return []
        self._open(file)
        logger.debug(f"[LSP request] goto references: {file}:{line}:{column}")

        try:
            locations = self.client.references(  # type: ignore
                TextDocumentIdentifier(uri=self._to_docker_uri(file)),
                lsp.Position(line=line, character=column),
                context=ReferenceContext(includeDeclaration=True),
            )
        except TimeoutError:
            logger.warning("LSP client timed out")
            return []

        logger.debug(f"[LSP response] goto references: {locations}")
        return self._normalize_locations(locations)

    def _to_docker_uri(self, file: Path) -> str:
        """Convert host file path to docker file URI"""
        if file.is_absolute():
            file = file.relative_to(self._source_directory)
        host_path = f"{self._source_directory_in_docker}/{file}"
        return f"file://{host_path}"

    def _to_host_path(self, uri: str) -> Path:
        """Convert docker file URI to host file path"""
        docker_path = uri.replace("file://", "").rstrip("/")
        assert docker_path.startswith(self._source_directory_in_docker)
        src_rel_path = docker_path[len(self._source_directory_in_docker) :]
        return self._source_directory / src_rel_path.lstrip("/")

    def _normalize_symbols(
        self, symbols: lsp.SymbolInformation | list[lsp.SymbolInformation]
    ) -> list[SymbolInformation]:
        if not isinstance(symbols, list):
            symbols = [symbols]
        normalized_symbols: list[SymbolInformation] = list()
        for symbol in symbols:
            normalized_symbols.append(
                SymbolInformation(
                    location=self._convert_location(symbol.location),
                    name=symbol.name,
                    containerName=symbol.containerName,
                )
            )

        return normalized_symbols

    def _normalize_locations(
        self,
        locations: lsp.Location | list[lsp.Location] | list[lsp.LocationLink],
    ) -> list[Location]:
        if not isinstance(locations, list):
            locations = [locations]
        locations = [
            location for location in locations if isinstance(location, lsp.Location)
        ]
        return [self._convert_location(location) for location in locations]

    def _convert_location(self, location: lsp.Location) -> Location:
        return Location(
            file=self._to_host_path(location.uri),
            range=location.range,
        )

    def _language_to_language_id(self, language: Language) -> LanguageIdentifier:
        match language:
            case "c":
                return LanguageIdentifier.C
            case "cpp" | "c++":
                return LanguageIdentifier.CPP
            case "jvm":
                return LanguageIdentifier.JAVA
