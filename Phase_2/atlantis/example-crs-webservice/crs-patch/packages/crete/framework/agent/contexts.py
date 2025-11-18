from pathlib import Path
from typing import NotRequired

from crete.atoms.action import Action
from crete.framework.evaluator.protocols import EvaluatorProtocol
from crete.framework.insighter.contexts import InsighterContext


class AgentContext(InsighterContext):
    previous_action: Action
    reflection: NotRequired[str]
    output_directory: NotRequired[Path]
    evaluator: EvaluatorProtocol
