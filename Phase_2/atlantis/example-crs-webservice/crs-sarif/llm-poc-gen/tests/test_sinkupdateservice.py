import logging
import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, AsyncMock

import aiofiles
import aiofiles.os
import pytest
import random

from tests.test_util import prepare_sample_cp
from vuli.blackboard import Blackboard
from vuli.common.setting import Setting
from vuli.cp import CP
from vuli.joern import CPG, Joern
from vuli.sink import Origin, SinkManager, SinkProperty
from vuli.sinkupdateservice import JavaCRS, SinkUpdateService, SarifUpdateTask
from vuli.sariflog import SarifLog
from vuli.struct import SinkCandidate, CodeLocation, VulInfo, CodeLocation
from vuli.query_loader import QueryLoader

@pytest.fixture(autouse=True)
def setup():
    asyncio.run(Blackboard().clear())
    asyncio.run(SinkManager().clear())


@pytest.mark.asyncio
@patch.object(Blackboard, "save")
@patch("vuli.sinkupdateservice.JavaCRS._get_from_joern")
async def test_sinkupdateservice_javacrs__update(patch_1, patch_2):
    patch_1.return_value = [
        {"name": "cls", "num": 1, "id": 0},
        {"name": "cls", "num": 2, "id": 1},
    ]
    t = await aiofiles.tempfile.NamedTemporaryFile()
    p = Path(t.name)
    src: dict = [
        {
            "coord": {"class_name": "cls", "line_num": 1},
            "type": ["sink-RegexInjection"],
            "in_diff": False,
            "sarif_reports": [],
        },
        {
            "coord": {"line": 3},
        },
        {
            "coord": {"class_name": "cls", "line_num": 2},
            "type": ["sink-deserialization"],
            "in_diff": True,
            "sarif_reports": [{"solved": True}, {"solved": False}],
        },
        {
            "coord": {"class_name": "cls", "line_num": 3},
            "type": ["sink-timeout"],
            "in_diff": False,
            "sarif_reports": [],
        },
    ]
    async with aiofiles.open(p, mode="w") as f:
        await f.write(json.dumps(src))
        await f.flush()

    task = JavaCRS(p)
    await task.run()
    sinks = await SinkManager().get()
    assert sinks[0] == SinkProperty(
        bug_types=set({"sink-RegexInjection"}), origins=set({Origin.FROM_CRS})
    )
    assert sinks[1] == SinkProperty(
        bug_types=set({"sink-deserialization"}),
        origins=set({Origin.FROM_CRS, Origin.FROM_DELTA, Origin.FROM_SARIF}),
    )


@pytest.mark.asyncio
@patch.object(Blackboard, "save")
@patch("vuli.sinkupdateservice.JavaCRS._get_from_joern")
async def test_sinkupdateservice_javacrs_run(patch_1, patch_2):
    async def writer(path: Path):
        await aiofiles.os.unlink(path)
        async with aiofiles.open(path, "w") as f:
            await f.write(
                json.dumps(
                    [
                        {
                            "coord": {"class_name": "cls", "line_num": 1},
                            "type": ["sink-RegexInjection"],
                            "in_diff": False,
                            "sarif_reports": [],
                        },
                    ]
                )
            )
            await f.flush()
            os.fsync(f.fileno())
        patch_1.return_value = [{"name": "cls", "num": 1, "id": 0}]
        while 0 not in await SinkManager().get():
            await asyncio.sleep(1)
            pass

        await aiofiles.os.unlink(path)
        async with aiofiles.open(path, "w") as f:
            await f.write(
                json.dumps(
                    [
                        {
                            "coord": {"class_name": "cls", "line_num": 2},
                            "type": ["sink-RegexInjection"],
                            "in_diff": False,
                            "sarif_reports": [],
                        },
                    ]
                )
            )
            await f.flush()
            os.fsync(f.fileno())
        patch_1.return_value = [{"name": "cls", "num": 2, "id": 1}]

    t = tempfile.NamedTemporaryFile()
    p = Path(t.name)
    service = SinkUpdateService(1)
    service.add_task(JavaCRS(p))
    tasks = [asyncio.create_task(service.run()), asyncio.create_task(writer(p))]
    try:
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=5)
    except asyncio.TimeoutError:
        pass
    sinks = await SinkManager().get()
    assert sinks[0] == SinkProperty(
        bug_types=set({"sink-RegexInjection"}), origins=set({Origin.FROM_CRS})
    )
    assert sinks[1] == SinkProperty(
        bug_types=set({"sink-RegexInjection"}), origins=set({Origin.FROM_CRS})
    )
    assert patch_2._mock_call_count == 2


@pytest.mark.asyncio
async def test_sinkupdateservice_javacrs_path_not_exist():
    await JavaCRS(None).run()


@pytest.mark.asyncio
@patch("vuli.sinkupdateservice.JavaCRS._parse")
async def test_sinkupdateservice_javacrs_same_mtime(patch_1):
    patch_1.return_value = []
    t = tempfile.NamedTemporaryFile()
    handler = JavaCRS(Path(t.name))
    await handler.run()
    await handler.run()
    patch_1.assert_called_once()


@pytest.mark.asyncio
async def test_sinkupdateservice_javacrs_invalid_file():
    t = tempfile.NamedTemporaryFile()
    await JavaCRS(Path(t.name)).run()


@pytest.mark.asyncio
@patch.object(Blackboard, "save")
async def test_sinkupdateservice_javacrs_e2e(patch_1):
    await prepare_sample_cp()
    t = tempfile.NamedTemporaryFile()
    p = Path(t.name)
    with p.open("w") as f:
        json.dump(
            [
                {
                    "coord": {"class_name": "sample.BugOne", "line_num": 6},
                    "type": ["sink-OsCommandInjection"],
                    "in_diff": False,
                    "sarif_reports": [],
                },
            ],
            f,
        )
    cpg = CPG(Setting().cpg_path)
    await cpg.build(
        Setting().joern_javasrc_path, CP().source_dir, [], CP().get_dependent_jars()
    )
    try:
        Joern().set_path(Setting().joern_cli_path)
        await Joern().run_server(cpg, Setting().query_path, Setting().semantic_dir)
        await JavaCRS(p).run()
    finally:
        await Joern().close_server()

    sinks = await SinkManager().get()
    id: int = list(sinks.keys())[0]
    assert sinks[id] == SinkProperty(
        bug_types=set({"sink-OsCommandInjection"}), origins=set({Origin.FROM_CRS})
    )


def pick_random_line(lines: list[int], max_response: int) -> dict:
    if len(lines) >= max_response:
        sampled = random.sample(lines, max_response)
    else:
        while True:
            sampled = random.choices(lines, k=max_response)
            if len(set(sampled)) > 1:
                break

    logging.debug(f"[pick_random_line] {lines} -> {sampled}")
    return {"line": sampled}


def generate_sink_candidates(
    file_paths: list[str],
    methods: list[str] = ["foo", "bar", "baz", "qux"],
    v_types = ["type 1", "type 2", "type 3", "type 4"],
    num_candidates: int = 5,
    max_groups: int = 1,
) -> tuple[list[list[SinkCandidate]], int]:
    random.seed(42)

    all_combinations = [(f, m, v) for f in file_paths for m in methods for v in v_types]
    chosen_keys = random.sample(all_combinations, k=min(max_groups, len(all_combinations)))

    group_map: dict[tuple[str, str, str], list[SinkCandidate]] = {k: [] for k in chosen_keys}
    used_lines: set[tuple[str, str, int]] = set()

    for _ in range(num_candidates):
        path, method, v_type = random.choice(chosen_keys)

        while True:
            line = random.randint(1, 1000)
            if (path, method, line) not in used_lines:
                used_lines.add((path, method, line))
                break

        candidate = SinkCandidate(
            v_type=v_type,
            v_point=CodeLocation(path=path, line=line),
            method=method,
            id=hash((path, method, line)) & 0x7FFFFFFF,
        )
        group_map[(path, method, v_type)].append(candidate)

    all_candidates = [group for group in group_map.values() if group]

    all_ids = [c.id for group in all_candidates for c in group]
    assert len(all_ids) == len(set(all_ids)), f"Duplicate IDs found: {all_ids}"
    
    for group in all_candidates:
        paths = {c.v_point.path for c in group}
        methods = {c.method for c in group}
        assert len(paths) == 1, f"Inconsistent paths in group: {paths}"
        assert len(methods) == 1, f"Inconsistent methods in group: {methods}"

    return all_candidates


def generate_additional_candidates(
    original_groups: list[list[SinkCandidate]]
) -> list[list[SinkCandidate]]:
    random.seed(42)

    additional_groups = []
    new_path = ["tmp1", "tmp2"]

    for group in original_groups:
        if not group:
            continue
        
        original_path = group[0].v_point.path
        if not original_path.endswith(".in"):
            continue

        method = group[0].method
        v_type = group[0].v_type

        for path in new_path:
            path = f"{path}/{original_path.removesuffix(".in")}"
            start_line = random.randint(1, 100)
            new_group = [
                SinkCandidate(
                    v_type=v_type,
                    v_point=CodeLocation(path=path, line=start_line + c.v_point.line),
                    method=method,
                    id=hash((path, method, c.v_point.line)) & 0x7FFFFFFF
                )
                for c in group
            ]

            additional_groups.append({
                "match": method,
                "candidates": new_group
            })
        
    all_ids = [c.id for group in additional_groups for c in group["candidates"]]
    assert len(all_ids) == len(set(all_ids)), f"Duplicate IDs found: {all_ids}"

    return additional_groups


@pytest.mark.asyncio
@patch.object(Blackboard, "save")
@patch("vuli.sariflog.SarifLog.extract", new_callable=AsyncMock)
@patch("vuli.cp.CP.get_harness_names")
@patch("vuli.sinkupdateservice.SarifUpdateTask.get_code", new_callable=AsyncMock)
@patch("vuli.model_manager.ModelManager.get_all_model_names")
@patch("vuli.model_manager.ModelManager.invoke", new_callable=AsyncMock)
async def test_sinkupdateservice_sarif__update(
    mock_invoke,
    mock_get_models,
    mock_get_code,
    mock_get_harness,
    mock_extract,
    mock_save
):
    QueryLoader().load(Path("queries/c.yaml"))

    max_response = 2
    sink_candidates = generate_sink_candidates(["a.c", "b.c", "c.c", "d.c"])

    mock_extract.return_value = (sink_candidates, [])
    mock_get_harness.return_value = ["harness_1", "harness_2"]
    mock_get_code.return_value = ["code"]
    mock_get_models.return_value = ["model_1", "model_2", "model_3"]
    multi_lines = [[c.v_point.line for c in group] for group in sink_candidates if len(group) > 1]
    mock_invoke.side_effect = [
        pick_random_line(lines, max_response=max_response)
        for lines in multi_lines
        for _ in range(0, len(mock_get_harness.return_value))
        for _ in range(0, len(mock_get_models.return_value))
    ]

    sarif_data = {
        "runs": [
            {
                "results": [
                    {
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "index": 0,
                                        "uri": "src/shell.c.in"
                                    },
                                    "region": {
                                        "startLine": 3089,
                                        "startColumn": 1,
                                        "endLine": 3121,
                                        "endColumn": 1
                                    }
                                }
                            }
                        ],
                        "ruleId": "CWE-125",
                        "rule": {"id": "CWE-125", "index": 0}
                    }
                ]
            }
        ]
    }

    async with aiofiles.tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        sarif_path = Path(tmp_file.name)

    async with aiofiles.open(sarif_path, mode="w") as f:
        await f.write(json.dumps(sarif_data))
        await f.flush()

    task = SarifUpdateTask(sarif_path, max_response=max_response)
    await task.run()

    use_llm_candidate_group = sum(1 for lines in multi_lines if len(lines) >= 2)
    assert mock_invoke.call_count == \
        len(mock_get_harness.return_value) * len(mock_get_models.return_value) * use_llm_candidate_group
    assert mock_save.called


@pytest.mark.asyncio
@patch.object(Blackboard, "save")
@patch("vuli.sariflog.SarifLog.extract", new_callable=AsyncMock)
@patch("vuli.cp.CP.get_harness_names")
@patch("vuli.sinkupdateservice.SarifUpdateTask.get_code", new_callable=AsyncMock)
@patch("vuli.model_manager.ModelManager.get_all_model_names")
@patch("vuli.model_manager.ModelManager.invoke", new_callable=AsyncMock)
async def test_sinkupdateservice_sarif__update_amalgation(
    mock_invoke,
    mock_get_models,
    mock_get_code,
    mock_get_harness,
    mock_extract,
    mock_save
):
    QueryLoader().load(Path("queries/c.yaml"))

    max_response = 2
    sink_candidates = generate_sink_candidates(
        ["a.c.in", "b.c.in", "c.c.in", "d.c.in"]
    )
    additional_candidates = generate_additional_candidates(sink_candidates)

    mock_extract.return_value = (sink_candidates, additional_candidates)
    mock_get_harness.return_value = ["harness_1", "harness_2"]
    mock_get_code.return_value = ["code"]
    mock_get_models.return_value = ["model_1", "model_2", "model_3"]
    
    multi_lines = []
    for group in sink_candidates:
        if len(group) > 1:
            multi_lines.append([c.v_point.line for c in group])
        for add_cand in additional_candidates:
            if add_cand["match"] == group[0].method:
                multi_lines.append([c.v_point.line for c in add_cand["candidates"]])

    mock_invoke.side_effect = [
        pick_random_line(lines, max_response=max_response)
        for lines in multi_lines
        for _ in range(0, len(mock_get_harness.return_value))
        for _ in range(0, len(mock_get_models.return_value))
    ]

    sarif_data = {
        "runs": [
            {
                "results": [
                    {
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "index": 0,
                                        "uri": "src/shell.c.in"
                                    },
                                    "region": {
                                        "startLine": 3089,
                                        "startColumn": 1,
                                        "endLine": 3121,
                                        "endColumn": 1
                                    }
                                }
                            }
                        ],
                        "ruleId": "CWE-125",
                        "rule": {"id": "CWE-125", "index": 0}
                    }
                ]
            }
        ]
    }

    async with aiofiles.tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        sarif_path = Path(tmp_file.name)

    async with aiofiles.open(sarif_path, mode="w") as f:
        await f.write(json.dumps(sarif_data))
        await f.flush()

    task = SarifUpdateTask(sarif_path, max_response=max_response)
    await task.run()
    sinks = await SinkManager().get()

    use_llm_candidate_group = sum(1 for lines in multi_lines if len(lines) >= 2)
    assert mock_invoke.call_count == \
        len(mock_get_harness.return_value) * len(mock_get_models.return_value) * use_llm_candidate_group
    assert mock_save.called
