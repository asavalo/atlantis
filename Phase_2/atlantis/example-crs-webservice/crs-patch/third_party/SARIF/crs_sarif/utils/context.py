import logging
import os
import shutil
import time
from pathlib import Path

import yaml

from crs_sarif.utils.cmd import rsync
from crs_sarif.utils.decorator import singleton
from libCRS.challenge import CP as libcrs_CP
from sarif.context import SarifEnv, SarifServerManager
from sarif.tools.codeql.queries import get_abs_path

logger = logging.getLogger(__name__)


@singleton
class CRSEnv:
    def __init__(
        self,
    ):
        logger.info("Initializing CRSEnv")

        self.crs_mode = os.getenv("CRS_MODE", "debug")
        if self.crs_mode == "debug":
            logger.info(f"ENV: {os.environ}")

        self.project_name = os.getenv("PROJECT_NAME")
        self.project_language = os.getenv("PROJECT_LANGUAGE")
        self.cp_proj_path = Path(os.getenv("CP_PROJ_PATH"))
        # self.cp_src_path = Path(os.getenv("CP_SRC_PATH"))
        self.cp_src_path = Path(os.getenv("SRC_DIR"))
        self.corpus_hash_engine_path = Path(os.getenv("CORPUS_HASH_ENGINE_PATH"))

        # Directories
        self.src_dir = Path(os.getenv("SRC_DIR"))
        if not self.src_dir.exists():
            self.src_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir = Path(os.getenv("OUT_DIR"))
        if not self.out_dir.exists():
            self.out_dir.mkdir(parents=True, exist_ok=True)
        self.build_dir = Path(os.getenv("BUILD_DIR"))
        if not self.build_dir.exists():
            self.build_dir.mkdir(parents=True, exist_ok=True)
        # self.oss_fuzz_dir = Path(os.getenv("OSS_FUZZ_DIR"))
        self.corpus_dir = self.out_dir / "corpus"
        if not self.corpus_dir.exists():
            self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.reachability_dir = self.out_dir / "reachability"
        if not self.reachability_dir.exists():
            self.reachability_dir.mkdir(parents=True, exist_ok=True)

        # Shared directories
        # Read only
        self.tarball_dir = Path(os.getenv("TARBALL_DIR"))
        self.multilang_build_dir = Path(os.getenv("MULTILANG_BUILD_DIR"))
        self.build_shared_dir = Path(os.getenv("BUILD_SHARED_DIR"))
        self.corpus_shared_dir = Path(os.getenv("CORPUS_SHARED_DIR"))
        self.coverage_shared_dir = Path(os.getenv("COVERAGE_SHARED_DIR"))

        # Read/Write
        self.reachability_shared_dir = Path(os.getenv("REACHABILITY_SHARED_DIR"))
        if not self.reachability_shared_dir.exists():
            self.reachability_shared_dir.mkdir(parents=True, exist_ok=True)
        self.call_trace_shared_dir = Path(os.getenv("CALL_TRACE_SHARED_DIR"))
        if not self.call_trace_shared_dir.exists():
            self.call_trace_shared_dir.mkdir(parents=True, exist_ok=True)
        self.original_sarif_shared_dir = Path(os.getenv("ORIGINAL_SARIF_SHARED_DIR"))
        if not self.original_sarif_shared_dir.exists():
            self.original_sarif_shared_dir.mkdir(parents=True, exist_ok=True)

        self.coverage_request_shared_dir = Path(
            os.getenv("COVERAGE_REQUEST_SHARED_DIR")
        )
        if not self.coverage_request_shared_dir.exists():
            self.coverage_request_shared_dir.mkdir(parents=True, exist_ok=True)

        self._wait_for_multilang_build()
        self._wait_for_tarball_extract()
        self._copy_config_yaml()

        self.cp = libcrs_CP(
            name=self.project_name,
            proj_path=self.cp_proj_path,
            cp_src_path=self.cp_src_path,
            built_path=None,
        )

        config_path = self.cp_proj_path / ".aixcc" / "config.yaml"
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        self.harness_files = config["harness_files"]

        # Language-specific settings
        self.java_cp_metadata_path = Path(os.getenv("JAVA_CP_METADATA_PATH"))

        self.analyser_init_done = False
        self.llm_poc_gen_init_done = False

        logger.info(f"CRSEnv: {vars(self)}")
        logger.info("CRSEnv initialized")

    def _wait_for_tarball_extract(self):
        logger.info("Waiting for tarball extraction")

        done_file = self.build_shared_dir / "EXTRACT_DONE"
        while not done_file.exists():
            time.sleep(1)

        logger.info("Tarball extraction done")

    def _wait_for_multilang_build(self):
        logger.info("Waiting for multilang build")

        done_file = self.multilang_build_dir / "DONE"
        config_file = self.multilang_build_dir / "aixcc_conf.yaml"
        while not done_file.exists() or not config_file.exists():
            time.sleep(1)

        logger.info("Multilang build done")

    def _copy_config_yaml(self):
        logger.info("Copying config.yaml from multilang_build_dir to cp_proj_path")

        rsync(
            self.multilang_build_dir / "aixcc_conf.yaml",
            self.cp_proj_path / ".aixcc" / "config.yaml",
        )

    def update_sarif_harness_paths_joern(self) -> None:
        logger.info("Updating sarif harness paths for joern")

        config_path = self.cp_proj_path / ".aixcc" / "config.yaml"

        with open(config_path, "r") as f:
            config_yaml_data = yaml.safe_load(f)

        for harness in SarifEnv().cp.harnesses:
            harness_file = [
                h
                for h in config_yaml_data["harness_files"]
                if h["name"] == harness.name
            ][0]
            rel_path = harness_file["path"].replace("$PROJECT", "").replace("$REPO", "")

            res = list(
                map(
                    tuple,
                    SarifServerManager().joern_server.query_json(
                        f"""\
                        cpg
                        .method
                        .filter {{ m =>
                            m.filename.endsWith("{rel_path}") &&
                            m.code != "<global>"
                        }}
                        .map {{ m =>
                            (m.filename, m.lineNumber, m.name).toList
                        }}
                        .toJson
                    """
                    ),
                )
            )

            abs_path = "/src/" + res[0][0]

            harness.path = Path(abs_path)

    async def update_sarif_harness_paths_codeql(self) -> None:
        config_path = self.cp_proj_path / ".aixcc" / "config.yaml"

        with open(config_path, "r") as f:
            config_yaml_data = yaml.safe_load(f)

        rel_paths = []
        for harness in config_yaml_data["harness_files"]:
            rel_path = harness["path"].replace("$PROJECT", "").replace("$REPO", "")
            rel_paths.append(rel_path)

        query = (
            get_abs_path("c")
            if self.project_language == "c"
            or self.project_language == "cpp"
            or self.project_language == "c++"
            else get_abs_path("java")
        )
        query_res = query.run(
            database=SarifEnv().codeql_db_path,
            params={"relative_paths": rel_paths},
        )
        results = query_res.parse()

        result_map = {result["base_name"]: result["abs_path"] for result in results}

        for harness in SarifEnv().cp.harnesses:
            for harness_config in config_yaml_data["harness_files"]:
                if harness_config["name"] == harness.name:
                    base_name = harness_config["path"].split("/")[-1]
                    if base_name in result_map:
                        harness.path = Path(result_map[base_name])
