from typing import Optional, Protocol
from uuid import UUID

from ..models import PatchRequest


class PatcherProtocol(Protocol):
    def patch(self, request: PatchRequest) -> Optional[str]: ...


class RequestHandlerProtocol(Protocol):
    async def put(self, request: PatchRequest) -> None: ...

    async def handle(self) -> None: ...


class SubmitterProtocol(Protocol):
    def submit(
        self, request: PatchRequest, patch: str, patched_again_pov_ids: list[UUID]
    ) -> None: ...
