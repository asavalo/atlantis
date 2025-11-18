from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.code_inspector.functions import (
    SymbolLocation,
    _find_symbol_locations_using_ripgrep,  # type: ignore
)
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment_pool.services.mock import MockEnvironmentPool
from crete.framework.evaluator.services.mock import MockEvaluator


@pytest.mark.slow
def test_find_symbol_locations_using_ripgrep(
    detection_cpp_example_libpng_cpv_0: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_cpp_example_libpng_cpv_0,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_cpp_example_libpng_cpv_0),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    symbol_locations = _find_symbol_locations_using_ripgrep(
        context=context,
        symbol_name="png_handle_iCCP",
    )
    assert (
        SymbolLocation(
            file=context["pool"].source_directory / "pngrutil.c",
            line=1373,
            column=0,
        )
        in symbol_locations
    )
