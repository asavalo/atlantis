import os
import tempfile
from pathlib import Path

import pytest
from crete.framework.language_parser.services.ctags import CtagsParser
from crete.framework.language_parser.services.ctags.models import TagKind


@pytest.fixture
def ctags_tmp_file():
    output_json = Path(tempfile.mktemp(suffix=".json"))
    try:
        yield output_json
    finally:
        if output_json.exists():
            os.remove(output_json)


@pytest.mark.slow
def test_get_all_functions(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
    ctags_tmp_file: Path,
):
    source_directory, _ = detection_c_asc_nginx_cpv_1
    ctags_parser = CtagsParser(source_directory, ctags_tmp_file, lang="c")
    function_entries = ctags_parser.get_all_functions()

    assert len(function_entries) == 2731


@pytest.mark.slow
def test_get_all_variables(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
    ctags_tmp_file: Path,
):
    source_directory, _ = detection_c_asc_nginx_cpv_1
    ctags_parser = CtagsParser(source_directory, ctags_tmp_file, lang="c")
    variable_entries = ctags_parser.get_all_variables()

    assert len(variable_entries) == 991


@pytest.mark.slow
def test_get_tag_entries_by_name(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
    ctags_tmp_file: Path,
):
    source_directory, _ = detection_c_asc_nginx_cpv_1
    ctags_parser = CtagsParser(source_directory, ctags_tmp_file, lang="c")

    entries = ctags_parser.get_tag_entries_by_name(
        "ngx_stream_upstream_empty_save_session"
    )

    assert len(entries) == 1

    target_entry = entries[0]
    assert target_entry.name == "ngx_stream_upstream_empty_save_session"
    assert target_entry.kind == TagKind.FUNCTION
    assert target_entry.rel_src_path == Path(
        "src/stream/ngx_stream_upstream_round_robin.c"
    )
    assert target_entry.line == 880
