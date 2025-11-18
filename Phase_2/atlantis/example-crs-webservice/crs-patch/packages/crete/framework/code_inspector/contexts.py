from python_oss_fuzz.language_server_protocol.actors import LspClient

from crete.framework.language_parser.protocols import LanguageParserProtocol
from crete.utils.language_server_protocol.contexts import LanguageServerProtocolContext


class CodeInspectorContext(LanguageServerProtocolContext):
    language_parser: LanguageParserProtocol
    lsp_client: LspClient
