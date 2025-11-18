from pydantic import BaseModel


class PatchSegment(BaseModel):
    patch_tag: str
    filename: str
    patch_code: str
    start_line: int
    end_line: int


class PatchFailure(BaseModel):
    invalid_segments: list[PatchSegment]
    reason: str
