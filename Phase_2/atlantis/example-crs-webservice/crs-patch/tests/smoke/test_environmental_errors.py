import importlib
import itertools
import json
from pathlib import Path
from typing import Any, cast

import pytest
from crete.atoms.action import UnknownErrorAction
from crete.atoms.path import PACKAGES_DIRECTORY
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.crete import Crete
from crete.framework.environment.exceptions import (
    ChallengeBuildFailedError,
    ChallengePoVFoundError,
    ChallengeTestFailedError,
    ChallengeWrongPatchError,
)
from pytest_mock import MockerFixture

EXCEPTION_BY_OPERATION = {
    "build": [
        # ChallengeNotPreparedError(),
        ChallengeBuildFailedError(b"", b""),
    ],
    "patch": [
        ChallengeWrongPatchError(b"", b""),
        ChallengeBuildFailedError(b"", b""),
    ],
    "run_tests": [
        ChallengeTestFailedError(b"", b""),
    ],
    "run_pov": [
        ChallengePoVFoundError(b"", b""),
    ],
}


MAX_OPERATIONS = 5
MAX_INDEX = MAX_OPERATIONS * sum(
    len(EXCEPTION_BY_OPERATION[key]) for key in EXCEPTION_BY_OPERATION.keys()
)


def _generate_faults(index: int) -> dict[str, list[Exception | None]]:
    assert index < MAX_INDEX

    current = 0
    for key in EXCEPTION_BY_OPERATION:
        for _, exc in enumerate(EXCEPTION_BY_OPERATION[key]):
            for pos in range(MAX_OPERATIONS):  # positions in the array
                if current != index:
                    current += 1
                    continue

                side_effect_by_operation: dict[str, list[Exception | None]] = {
                    "build": [None] * MAX_OPERATIONS,
                    "patch": [None] * MAX_OPERATIONS,
                    "run_tests": [None] * MAX_OPERATIONS,
                    "run_pov": [None] * MAX_OPERATIONS,
                }
                side_effect_by_operation[key][pos] = exc
                return side_effect_by_operation

    assert False, "Unreachable"


def _inject_faults(
    mocker: MockerFixture, side_effect_by_operation: dict[str, list[Exception | None]]
):
    for key, side_effect in side_effect_by_operation.items():
        print(key, side_effect)
        mocker.patch(
            "crete.framework.environment.services.oss_fuzz.default.OssFuzzEnvironment."
            + key,
            side_effect=side_effect,
        )


@pytest.fixture
def fault_injection(mocker: MockerFixture, index: int):
    side_effect_by_operation = _generate_faults(index)
    _inject_faults(mocker, side_effect_by_operation)


def load_modules() -> list[str]:
    module_types: set[str] = set()
    modules: list[str] = []
    configs = json.load(open(PACKAGES_DIRECTORY / "crs_patch/configs.json"))
    for config in configs:
        candidates = config["module"].split(":")
        for candidate in candidates:
            name = candidate.split(".")[1]
            if name not in module_types and name != "eraser":
                module_types.add(name)
                modules.append(candidate)
    return modules


@pytest.mark.smoke
@pytest.mark.parametrize(
    "index, module", itertools.product(range(MAX_INDEX), load_modules())
)
def test_agents_with_faults(
    detection_c_mock_c_cpv_0: tuple[Path, Path], module: str, fault_injection: Any
):
    app = cast(Crete, getattr(importlib.import_module(module), "app"))
    context_builder = AIxCCContextBuilder(
        *detection_c_mock_c_cpv_0,
    )

    action = app.run(context_builder, timeout=10, llm_cost_limit=5)
    assert not isinstance(action, UnknownErrorAction)
