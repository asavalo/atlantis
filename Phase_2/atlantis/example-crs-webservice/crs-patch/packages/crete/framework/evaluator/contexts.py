from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment_pool.protocols import EnvironmentPoolProtocol


class EvaluatingContext(EnvironmentContext):
    pool: EnvironmentPoolProtocol
