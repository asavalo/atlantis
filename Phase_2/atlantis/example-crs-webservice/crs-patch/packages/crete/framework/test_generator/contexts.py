from crete.atoms.detection import Detection
from crete.framework.environment.protocols import EnvironmentProtocol
from crete.framework.environment_pool.protocols import EnvironmentPoolProtocol
from crete.framework.evaluator.contexts import EvaluatingContext
from crete.framework.language_parser.protocols import LanguageParserProtocol


class TestGenerationContext(EvaluatingContext):
    language_parser: LanguageParserProtocol
    environment: EnvironmentProtocol
    pool: EnvironmentPoolProtocol
    detection: Detection
