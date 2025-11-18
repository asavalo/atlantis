from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from my_crs.task_server.models.types import (
    Task,
    TaskDetail,
)


class State(Enum):
    Canceled = "canceled"
    Cancelling = "cancelling"
    Errored = "errored"
    Pending = "pending"
    Running = "running"
    Succeeded = "succeeded"
    Waiting = "waiting"


class TaskStatus(BaseModel):
    detail: Optional[TaskDetail] = None
    state: State
    cp_manager_service: Optional[str] = None


class SubCRSStatus(BaseModel):
    state: str
    subcrs_service: Optional[str]


class DeployRequest(BaseModel):
    deploy_request_id: str
    deploy_requests: List[DeployRequestDetail]


class DeployRequestDetail(BaseModel):
    template: str = Field(
        ...,
        description="The name / key used to find the template function in template.py.",
    )
    new_node_count: int = Field(
        1, description="The number of new nodes that should be made."
    )
    args: List[Any] = Field(
        [], description="A list of arguments to pass to the template function."
    )
    kwargs: Dict[str, Any] = Field(
        {},
        description="A dict of keyword arguments to pass to the template function.",
    )
