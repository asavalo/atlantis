from pathlib import Path

from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.insighter.services.segmented_file import (
    SegmentedFileInsighter,
    _merge_segments,  # pyright: ignore[reportPrivateUsage]
)


def test_merge_segments():
    for segments, expected in [
        # No overlap
        ([(0, 1), (2, 3), (4, 5), (6, 7)], [(0, 1), (2, 3), (4, 5), (6, 7)]),
        # Overlap
        ([(0, 1), (1, 3), (3, 5), (5, 7)], [(0, 7)]),
        # Overlap but not sorted
        ([(5, 7), (3, 5), (1, 3), (0, 1)], [(0, 7)]),
        # Equivalent
        ([(0, 1), (0, 1)], [(0, 1)]),
    ]:
        merged_segments = _merge_segments(segments)
        assert merged_segments == expected


def test_mock_cp(detection_c_mock_cp_cpv_1: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    file = context["pool"].source_directory / "mock_vp.c"
    segments = [(10, 12), (14, 16)]
    insighter = SegmentedFileInsighter(file, segments)
    insight = insighter.create(context, detection)
    assert insight is not None
    assert (
        insight
        == r"""### File: mock_vp.c

...
10|         printf("input item:");
11|         buff = &items[i][0];
...
...
14|         buff[strcspn(buff, "\n")] = 0;
15|     }while(strlen(buff)!=0);
...
"""
    )
