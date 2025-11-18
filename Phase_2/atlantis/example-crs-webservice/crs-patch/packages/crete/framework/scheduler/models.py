from typing import TypeAlias

from crete.atoms.action import Action
from crete.framework.agent.protocols import AgentProtocol

ActionHistory: TypeAlias = list[Action]
AgentQueue: TypeAlias = dict[AgentProtocol, ActionHistory]
