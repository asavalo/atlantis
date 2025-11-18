from typing import Any, Protocol
from crete.framework.agent.services.vincent.states.patch_state import (
    PatchState,
)


class BaseNode(Protocol):
    def __call__(self, state: PatchState) -> dict[str, Any]: ...

    def _get_dict_from_state(self, state: PatchState) -> dict[str, Any]:
        return {
            "model_config": state.model_config,
            "patch_stage": state.patch_stage,
            "messages": state.messages,
            "diff": state.diff,
            "detection": state.detection,
            "requests": state.requests,
            "rca_report": state.rca_report,
            "properties": state.properties,
            "action": state.action,
            "feedback_cnt": state.feedback_cnt,
        }
