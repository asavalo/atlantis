import random
from pathlib import Path
from typing import Literal, TypeAlias

from pydantic import BaseModel, Field

_Variant: TypeAlias = Literal[
    "sound",
    "vulnerable",
    "compilable",
    "uncompilable",
    "wrong",
    "no_patch",
    "unknown_error",
    "head",
]


class BaseAction(BaseModel):
    variant: _Variant


class DiffAction(BaseAction):
    diff: bytes

    def __str__(self):
        return f"{self.variant.capitalize()}DiffAction(diff={self.diff})"


class SoundDiffAction(DiffAction):
    variant: _Variant = Field(default="sound")
    diff: bytes


class VulnerableDiffAction(DiffAction):
    variant: _Variant = Field(default="vulnerable")
    diff: bytes
    stdout: bytes
    stderr: bytes


class CompilableDiffAction(DiffAction):
    variant: _Variant = Field(default="compilable")
    diff: bytes
    stdout: bytes
    stderr: bytes


class UncompilableDiffAction(DiffAction):
    variant: _Variant = Field(default="uncompilable")
    diff: bytes
    stdout: bytes
    stderr: bytes


class WrongDiffAction(DiffAction):
    variant: _Variant = Field(default="wrong")
    diff: bytes
    stdout: bytes
    stderr: bytes


class NoPatchAction(BaseAction):
    variant: _Variant = Field(default="no_patch")

    def __str__(self):
        return "NoPatchAction()"


class UnknownErrorAction(BaseAction):
    variant: _Variant = Field(default="unknown_error")
    error: Exception

    model_config = {"arbitrary_types_allowed": True}

    def __str__(self):
        return f"UnknownErrorAction(error={self.error})"


class HeadAction(BaseAction):
    variant: _Variant = Field(default="head")

    def __str__(self):
        return "HeadAction()"


Action: TypeAlias = (
    SoundDiffAction
    | VulnerableDiffAction
    | CompilableDiffAction
    | UncompilableDiffAction
    | WrongDiffAction
    | NoPatchAction
    | UnknownErrorAction
    | HeadAction
)


# TODO(v4): rename to save_action
def store_action(action: Action, output_directory: Path, prefix: str) -> None:
    (output_directory / f"{prefix}-action.json").write_text(
        action.model_dump_json(indent=2)
    )

    match action:
        case HeadAction():
            (output_directory / f"{prefix}-action-head.empty").touch()
        case SoundDiffAction(variant=variant, diff=diff):
            (output_directory / f"{prefix}-action-sound.diff").write_bytes(diff)
        case (
            VulnerableDiffAction(variant=variant, diff=diff)
            | CompilableDiffAction(variant=variant, diff=diff)
            | UncompilableDiffAction(variant=variant, diff=diff)
            | WrongDiffAction(variant=variant, diff=diff)
        ):
            (output_directory / f"{prefix}-action-{variant}.diff").write_bytes(diff)
            (output_directory / f"{prefix}-action-{variant}.stdout").write_bytes(
                action.stdout
            )
            (output_directory / f"{prefix}-action-{variant}.stderr").write_bytes(
                action.stderr
            )
        case NoPatchAction():
            (output_directory / f"{prefix}-action-no_patch.empty").touch()
        case UnknownErrorAction(error=error):
            with open(
                output_directory / f"{prefix}-action-unknown_error.error", "w"
            ) as f:
                f.write(f"Exception type: {type(error).__name__}\n")
                f.write(f"Exception message: {str(error)}\n")


# TODO: Implement voting mechanism
def choose_best_action(actions: list[Action]) -> Action:
    assert len(actions) >= 1, "To choose the best action, at least one action is needed"
    score = {
        "SoundDiffAction": 4,
        "VulnerableDiffAction": 3,
        "CompilableDiffAction": 3,
        "UncompilableDiffAction": 2,
        "WrongDiffAction": 1,
        "NoPatchAction": 0,
        "UnknownErrorAction": -1,
        "HeadAction": -2,
    }
    max_score = max(map(lambda action: score[type(action).__name__], actions))
    best_actions = [
        action for action in actions if score[type(action).__name__] == max_score
    ]
    return random.choice(best_actions)
