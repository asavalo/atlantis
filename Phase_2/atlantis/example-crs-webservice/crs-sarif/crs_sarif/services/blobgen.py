import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from pydantic_settings import BaseSettings

from crs_sarif.utils.context import CRSEnv
from crs_sarif.utils.redis_util import RedisUtil
from sarif.context import SarifEnv
from libCRS.otel import install_otel_logger

install_otel_logger(action_name="blobgen")
logger = logging.getLogger(__name__)


class PocGenConfig(BaseSettings):
    root_dir: str
    joern_dir: Path
    output_dir: Path
    work_dir: Path
    cp_name: str
    repo_src_path: Path
    debug_src_dir: Path
    debug_bin_dir: Path
    cp_meta: Optional[str] = None
    sarif: Optional[str] = None
    shared_dir: Path

    class Config:
        env_prefix = "POCGEN_"

    def update(self, sarif: str = "", cp_meta: str = "") -> None:
        if sarif:
            self.sarif = sarif
            # try:
            #     sarif = Path(sarif)
            #     if not sarif.is_absolute():
            #         sarif = self.output_dir / sarif
            #     self.sarif = str(sarif.resolve(strict=False))
            # except Exception:
            #     self.sarif = sarif
        if cp_meta:
            self.cp_meta = cp_meta
            # try:
            #     cp_meta = Path(cp_meta)
            #     if not cp_meta.is_absolute():
            #         cp_meta = self.output_dir / cp_meta
            #     self.cp_meta = str(cp_meta.resolve(strict=False))
            # except Exception:
            #     self.cp_meta = cp_meta


class HarnessManager:
    def __init__(self):
        self.harnesses: List[Tuple[str, Path, Optional[str]]] = []

    def load_from_yaml(self, yaml_path: Path) -> None:
        with open(yaml_path, "r") as f:
            yaml_data = yaml.safe_load(f)
        self.harnesses = [
            (h["name"], Path(h["path"]), None)
            for h in yaml_data.get("harness_files", [])
        ]

    def update_paths(self, project_root: Path, cp_src_path: Path) -> None:
        updated = []
        for name, path, typ in self.harnesses:
            path_str = path.as_posix()
            if "$PROJECT/" in path_str:
                path = project_root / path_str.split("$PROJECT/")[1]
                typ = "PROJECT"
            elif "$REPO/" in path_str:
                path = cp_src_path / path_str.split("$REPO/")[1]
                typ = "REPO"
            updated.append((name, path, typ))
        self.harnesses = updated


class PocGenRunner:
    def __init__(self, config: PocGenConfig):
        self.config = config

    async def run(self, sarif, metadata, sarif_id) -> None:
        output_dir = Path(self.config.output_dir) / str(sarif_id)

        if output_dir.exists():
            shutil.rmtree(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        log_path = output_dir / "log"
        cp_meta_path = output_dir / self.config.cp_meta
        sarif_path = output_dir / self.config.sarif

        cpg_path = SarifEnv(check_initialized=True).joern_cpg_path
        if not cpg_path.exists():
            return
        shutil.copy(cpg_path, Path(self.config.output_dir) / "cpg")

        with open(cp_meta_path, "w") as f:
            metadata["sinkpoint_path"] = str(sarif_path)
            json.dump(metadata, f, indent=4)
        with open(sarif_path, "w") as f:
            json.dump(sarif, f, indent=4)

        env = os.environ.copy()
        env.pop("VIRTUAL_ENV", None)
        env.pop("PYTHONPATH", None)

        log_path = open(log_path, "w")

        command = (
            "python3.12 -m vuli.main "
            "--mode=c_sarif "
            "--query=c.yaml "
            f"--joern_dir={self.config.joern_dir} "
            f"--shared_dir={self.config.shared_dir} "
            f"--output_dir={output_dir.resolve()} "
            f"--cp_meta={cp_meta_path.resolve()} "
            "--log_level=INFO "
            # "--model_cache=cache "
            # "--dev"
        )

        logger.info(
            f"joern_dir={self.config.joern_dir}, "
            f"shared_dir={self.config.shared_dir}, "
            f"output_dir={output_dir.resolve()}, "
            f"metadata={metadata}"
        )

        process = await asyncio.create_subprocess_shell(
            command,
            cwd=self.config.root_dir,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        async for line in process.stdout:
            line = line.decode().rstrip()
            logger.info(f"[blobgen] {line}")
            log_path.write(line + "\n")
            log_path.flush()

        await process.wait()
        log_path.close()


class Runner:
    def __init__(self, config: PocGenConfig):
        self.config = config
        self.harness_manager = HarnessManager()

    def _get_project_data(self) -> dict:
        with open(self.config.work_dir / "project.yaml", "r") as f:
            return yaml.safe_load(f)

    def setup_metadata(self) -> None:
        project_data = self._get_project_data()
        repo_name = Path(project_data.get("main_repo", "")).stem.replace(".git", "")
        config_path = self.config.work_dir / ".aixcc/config.yaml"

        self.harness_manager.load_from_yaml(config_path)
        self.harness_manager.update_paths(
            self.config.repo_src_path
            / "fuzz-tooling"
            / "projects"
            / self.config.cp_name,
            self.config.repo_src_path / repo_name,
        )

    def dump_metadata(self) -> dict:
        harnesses: Dict[str, Dict[str, str]] = {}
        for name, path, typ in self.harness_manager.harnesses:
            rel_src = path.relative_to(self.config.repo_src_path)
            if typ == "PROJECT":
                src_path = rel_src.relative_to(
                    Path(f"fuzz-tooling/projects/") / self.config.cp_name
                )
            elif typ == "REPO":
                parts = rel_src.parts
                src_path = Path(*parts[1:])
            else:
                src_path = path

            bin_path = Path(self.config.debug_bin_dir) / name
            harnesses[name] = {
                "name": name,
                "src_path": str(src_path),
                "bin_path": str(bin_path),
            }

        metadata = {
            "built_path": str(self.config.debug_bin_dir),
            "cp_full_src": str(self.config.debug_src_dir),
            "cp_name": self.config.cp_name,
            "harnesses": harnesses,
        }

        return metadata

    async def run(self, sarif, sarif_id) -> None:
        self.setup_metadata()
        cp_meta = self.dump_metadata()
        await PocGenRunner(self.config).run(sarif, cp_meta, sarif_id)


async def blobgen(sarif: Dict[str, Any], sarif_id):
    if sarif is None:
        return

    if CRSEnv().llm_poc_gen_init_done:
        config = PocGenConfig()
        config.update(sarif="sarif.json", cp_meta="metadata.json")
        logger.info(f"Running blobgen for sarif match request: sarif_id={sarif_id}")
        await Runner(config).run(sarif, sarif_id)
    else:
        logger.warning(
            "llm-poc-gen is not initialized, will run blobgen after llm-poc-gen is initialized"
        )
