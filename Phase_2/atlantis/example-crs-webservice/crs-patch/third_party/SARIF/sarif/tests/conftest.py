import os
from pathlib import Path

import pytest
from click.testing import CliRunner
from dotenv import load_dotenv
from loguru import logger

from sarif.context import SarifEnv, init_context
from sarif.models import CP, CodeLocation, File, Function, SarifInfo
from sarif.validator.preprocess.info_extraction import extract_essential_info

CP_ARGS = [
    {
        "name": "mock-c",
        "language": "c",
    },
]


@pytest.fixture(scope="session", autouse=True)
def load_env():
    load_dotenv()


@pytest.fixture(scope="session")
def runner():
    return CliRunner()


@pytest.fixture(scope="session", params=CP_ARGS)
def cp_args(request) -> dict:
    name = request.param["name"]
    language = request.param["language"]
    oss_fuzz_dir = os.getenv("OSS_FUZZ_DIR", "/home/user/work/team-atlanta/oss-fuzz")
    oss_fuzz_lang = language if language != "java" else "jvm"
    config_path = (
        f"{oss_fuzz_dir}/projects/aixcc/{oss_fuzz_lang}/{name}/.aixcc/config.yaml"
    )

    return {
        "name": name,
        "language": language,
        "config_path": config_path,
    }


@pytest.fixture(scope="session")
def cp(cp_args) -> CP:
    return CP(**cp_args)


@pytest.fixture(scope="session")
def c_cp():
    language = "c"
    name = "asc-nginx"

    oss_fuzz_dir = os.getenv("OSS_FUZZ_DIR", "/home/user/work/team-atlanta/oss-fuzz")
    oss_fuzz_lang = "c"
    config_path = (
        f"{oss_fuzz_dir}/projects/aixcc/{oss_fuzz_lang}/{name}/.aixcc/config.yaml"
    )

    return CP(
        name=name,
        language=language,
        config_path=config_path,
    )


# @pytest.fixture(scope="session", autouse=True)
# def init_c_sarif_context(c_cp: CP):
#     init_context(cp=c_cp, env_mode="local", debug_mode="debug")


@pytest.fixture(scope="session")
def jenkins_cp():
    language = "java"
    name = "jenkins"

    oss_fuzz_dir = os.getenv("OSS_FUZZ_DIR", "/home/user/work/team-atlanta/oss-fuzz")
    oss_fuzz_lang = "jvm"
    config_path = (
        f"{oss_fuzz_dir}/projects/aixcc/{oss_fuzz_lang}/{name}/.aixcc/config.yaml"
    )

    return CP(
        name=name,
        language=language,
        config_path=config_path,
    )


# @pytest.fixture(scope="session", autouse=True)
# def init_java_sarif_context(java_cp: CP):
#     init_context(cp=java_cp, env_mode="local", debug_mode="debug")


# @pytest.fixture(scope="session", autouse=True)
# def init_sarif_context(cp: CP):
#     init_context(cp=cp, env_mode="local", debug_mode="debug")


TP_SARIF_NAMES = [
    "cpv-0.sarif",
    "cpv-1.sarif",
    "cpv-2.sarif",
    "cpv-3.sarif",
]


@pytest.fixture(scope="session", params=TP_SARIF_NAMES)
def tp_sarif_path(cp: CP, request) -> Path | None:
    data_dir = os.getenv("DATA_DIR", "/home/user/work/team-atlanta/SARIF/sarif/data")

    sarif_name = request.param

    sarif_path = Path(f"{data_dir}/{cp.language}/out/sarif/{cp.name}_{sarif_name}")

    if sarif_path.exists():
        return sarif_path
    else:
        pytest.skip(f"Sarif file {sarif_path} does not exist")


def _sarif_info_to_code_location(sarif_info: SarifInfo) -> CodeLocation:
    return sarif_info.code_location


@pytest.fixture(scope="session")
def tp_sarif_info(cp: CP, tp_sarif_path: Path) -> SarifInfo:
    init_context(cp, env_mode="local", debug_mode="debug")
    return extract_essential_info(tp_sarif_path)


@pytest.fixture(scope="session")
def tp_sink_location(cp: CP, tp_sarif_info: SarifInfo) -> CodeLocation:
    return _sarif_info_to_code_location(tp_sarif_info)


FP_SARIF_NAMES = [
    "codeql_0.sarif",
    "snyk_0.sarif",
    "semgrep_0.sarif",
    "codeql_1.sarif",
    "snyk_1.sarif",
    "semgrep_1.sarif",
]


@pytest.fixture(scope="session", params=FP_SARIF_NAMES)
def fp_sarif_path(cp: CP, request) -> Path | None:
    sarif_name = request.param

    sarif_path = Path(f"../benchmarks/refined/{cp.language}/{cp.name}/{sarif_name}")

    if sarif_path.exists():
        return sarif_path
    else:
        pytest.skip(f"Sarif file {sarif_path} does not exist")


@pytest.fixture(scope="session")
def fp_sarif_info(cp: CP, fp_sarif_path: Path) -> SarifInfo:
    init_context(cp, env_mode="local", debug_mode="debug")
    return extract_essential_info(fp_sarif_path)


@pytest.fixture(scope="session")
def fp_sink_location(fp_sarif_info: SarifInfo) -> CodeLocation:
    return _sarif_info_to_code_location(fp_sarif_info)


@pytest.fixture(scope="session")
def jenkins_cp():
    language = "java"
    name = "jenkins"

    oss_fuzz_dir = os.getenv("OSS_FUZZ_DIR", "/home/user/work/team-atlanta/oss-fuzz")
    oss_fuzz_lang = "jvm"
    config_path = (
        f"{oss_fuzz_dir}/projects/aixcc/{oss_fuzz_lang}/{name}/.aixcc/config.yaml"
    )

    return CP(
        name=name,
        language=language,
        config_path=config_path,
    )


# @pytest.fixture(scope="session", autouse=True)
# def init_jenkins_sarif_context(jenkins_cp: CP):
#     logger.info(f"Initializing jenkins sarif context for {jenkins_cp.name}")
#     init_context(cp=jenkins_cp, env_mode="local", debug_mode="debug")
#     logger.info(
#         f"Jenkins sarif context initialized for {jenkins_cp.name}. class_dir = {SarifEnv().class_dir}"
#     )


JENKINS_TP_SARIF_NAMES = [
    "jenkins_JenkinsFiveCPVOne.sarif",
    "jenkins_JenkinsFourCPVTwo.sarif",
    "jenkins_JenkinsThreeCPVEight.sarif",
    "jenkins_JenkinsThreeCPVFour.sarif",
    "jenkins_JenkinsThreeCPVSeven.sarif",
    # "jenkins_JenkinsThreeCPVThree.sarif",
    # "jenkins_JenkinsFiveCPVTwo.sarif",
    # "jenkins_JenkinsOneCPVOne.sarif",
    # "jenkins_JenkinsThreeCPVEleven.sarif",
    # "jenkins_JenkinsThreeCPVNine.sarif",
    # "jenkins_JenkinsThreeCPVSix.sarif",
    # "jenkins_JenkinsThreeCPVTwo.sarif",
    # "jenkins_JenkinsFourCPVOne.sarif",
    # "jenkins_JenkinsOneCPVTwo.sarif",
    # "jenkins_JenkinsThreeCPVFive.sarif",
]

JENKINS_FP_SARIF_NAMES = [
    "codeql_0.sarif",
    "snyk_0.sarif",
    "semgrep_0.sarif",
    "codeql_1.sarif",
    "snyk_1.sarif",
    "semgrep_1.sarif",
]


@pytest.fixture(scope="session", params=JENKINS_TP_SARIF_NAMES)
def jenkins_tp_sarif_path(jenkins_cp: CP, request) -> Path | None:
    data_dir = os.getenv("DATA_DIR", "/home/user/work/team-atlanta/SARIF/sarif/data")

    sarif_name = request.param

    sarif_path = Path(
        f"{data_dir}/{jenkins_cp.language}/out/sarif/{jenkins_cp.name}_{sarif_name}"
    )

    if sarif_path.exists():
        return sarif_path
    else:
        pytest.skip(f"Sarif file {sarif_path} does not exist")


@pytest.fixture(scope="session")
def jenkins_tp_sarif_info(jenkins_cp: CP, jenkins_tp_sarif_path: Path) -> SarifInfo:
    init_context(jenkins_cp, env_mode="local", debug_mode="debug")
    return extract_essential_info(jenkins_tp_sarif_path)


@pytest.fixture(scope="session")
def jenkins_tp_sink_location(
    jenkins_cp: CP, jenkins_tp_sarif_info: SarifInfo
) -> CodeLocation:
    return _sarif_info_to_code_location(jenkins_tp_sarif_info)


@pytest.fixture(scope="session", params=JENKINS_FP_SARIF_NAMES)
def jenkins_fp_sarif_path(jenkins_cp: CP, request) -> Path | None:
    sarif_name = request.param

    sarif_path = Path(
        f"../benchmarks/refined/{jenkins_cp.language}/{jenkins_cp.name}/{sarif_name}"
    )

    if sarif_path.exists():
        return sarif_path
    else:
        pytest.skip(f"Sarif file {sarif_path} does not exist")


@pytest.fixture(scope="session")
def jenkins_fp_sarif_info(jenkins_cp: CP, jenkins_fp_sarif_path: Path) -> SarifInfo:
    init_context(jenkins_cp, env_mode="local", debug_mode="debug")
    return extract_essential_info(jenkins_fp_sarif_path)


@pytest.fixture(scope="session")
def jenkins_fp_sink_location(
    jenkins_cp: CP, jenkins_fp_sarif_info: SarifInfo
) -> CodeLocation:
    return _sarif_info_to_code_location(jenkins_fp_sarif_info)
