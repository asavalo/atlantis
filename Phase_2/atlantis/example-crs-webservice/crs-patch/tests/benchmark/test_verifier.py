from pathlib import Path

from python_oss_fuzz.path.globals import OSS_FUZZ_DIRECTORY

from scripts.benchmark.verifiers import verify_patch_with_patch_checker


def test_verify_patch_with_patch_checker(detection_c_mock_c_cpv_0: tuple[Path, Path]):
    source_directory, detection_file = detection_c_mock_c_cpv_0
    good_patch_file = (
        OSS_FUZZ_DIRECTORY
        / "projects/aixcc/c/mock-c/.aixcc/patches/fuzz_process_input_header/cpv_0.diff"
    )

    result = verify_patch_with_patch_checker(
        detection_file,
        source_directory,
        good_patch_file,
    )
    assert result.variant == "sound"
