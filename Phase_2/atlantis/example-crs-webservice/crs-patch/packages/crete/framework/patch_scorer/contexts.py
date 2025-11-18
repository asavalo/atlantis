from crete.framework.evaluator.contexts import EvaluatingContext
from crete.framework.language_parser.protocols import LanguageParserProtocol


class PatchScoringContext(EvaluatingContext):
    language_parser: LanguageParserProtocol
