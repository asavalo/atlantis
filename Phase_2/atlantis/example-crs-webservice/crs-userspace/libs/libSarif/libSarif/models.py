from pydantic import BaseModel
from enum import Enum
from pathlib import Path


class CallType(Enum):
    DIRECT = "direct"
    INDIRECT = "indirect"
    POLYMORPHIC = "poly"
    DYNAMIC = "dynamic"


class EdgeType(Enum):
    STRONG = "strong"
    WEAK = "weak"

    @classmethod
    def from_call_type(cls, call_type: CallType) -> "EdgeType":
        match call_type:
            case CallType.DIRECT:
                return EdgeType.STRONG
            case CallType.INDIRECT:
                return EdgeType.WEAK
            case CallType.POLYMORPHIC:
                # TODO: strong or weak?
                # return EdgeType.WEAK
                return EdgeType.STRONG
            case CallType.DYNAMIC:
                return EdgeType.STRONG


class Harness(BaseModel):
    name: str
    path: Path
    class_paths: list[Path] = []  # for java


class Function(BaseModel):
    func_name: str
    file_name: str | None  # absolute path
    class_name: str | None = None
    func_sig: str | None = None
    method_desc: str | None = None
    start_line: int | None = None
    end_line: int | None = None

    def __hash__(self):
        # if self.func_sig is not None:
        #     hash_value = self.func_sig + "@" + self.file_name
        if self.class_name is not None:
            hash_value = self.class_name + "." + self.func_name
        else:
            hash_value = self.func_name + "@" + self.file_name
        return hash(hash_value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Function):
            return False

        if self.class_name is not None and other.class_name is not None:
            class_name_eq = self.class_name == other.class_name
        else:
            class_name_eq = True

        if self.func_sig is not None and other.func_sig is not None:
            func_sig_eq = self.func_sig == other.func_sig
        else:
            func_sig_eq = True

        file_name_eq = self.file_name.endswith(
            other.file_name
        ) or other.file_name.endswith(self.file_name)
        func_name_eq = self.func_name == other.func_name

        return file_name_eq and func_name_eq and class_name_eq and func_sig_eq
