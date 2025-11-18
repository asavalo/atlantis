from typing import Protocol

from crete.atoms.action import Action


class ReflectorProtocol(Protocol):
    def reflect(self, previous_actions: list[Action]) -> str | None: ...
