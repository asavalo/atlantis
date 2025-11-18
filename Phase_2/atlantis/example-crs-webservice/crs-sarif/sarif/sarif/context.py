import logging
import os
from importlib import resources
from pathlib import Path
from typing import Literal

import joblib
import yaml
from dotenv import load_dotenv
from loguru import logger
from phoenix.otel import register
from pydantic import BaseModel

from sarif.models import CP, SarifConfig
from sarif.utils.code_context import CodeContextManager
from sarif.utils.logger import init_logger


class EnvNotFoundError(Exception): ...


class SingletonDependencyError(Exception): ...


def singleton(cls):
    _instances = {}

    def get_instance(
        *args, force_new_instance=False, check_initialized=False, **kwargs
    ):

        if check_initialized and cls not in _instances:
            raise SingletonDependencyError(
                f"Singleton instance {cls} is not initialized"
            )

        if force_new_instance or cls not in _instances:
            _instances[cls] = cls(*args, **kwargs)

        return _instances[cls]

    return get_instance


class Temperature(BaseModel):
    default: float
    eval: float
    branch: float


TEMPERATURE_SETTING = Literal[
    "default",
    "zero",
    "low",
    "medium",
    "high",
]


@singleton
class SarifLLMManager:
    ZERO = 0
    LOW = 0.2
    MEDIUM = 0.5
    HIGH = 1.0
    PEAK = 1.5

    # (default, eval, branch)
    temperatures = {
        "default": (MEDIUM, ZERO, HIGH),
        "zero": (ZERO, ZERO, ZERO),
        "low": (LOW, LOW, LOW),
        "medium": (MEDIUM, MEDIUM, MEDIUM),
        "high": (HIGH, HIGH, HIGH),
    }

    def __init__(self, temperature_setting: TEMPERATURE_SETTING = "default"):
        default, eval, branch = self.temperatures[temperature_setting]
        self.temperature = Temperature(default=default, eval=eval, branch=branch)


@singleton
class SarifCodeContextManager(CodeContextManager):
    def __init__(self, src_dir: str, out_dir: str):
        super().__init__(language="C", src_dir=src_dir, out_dir=out_dir)


@singleton
class SarifCacheManager:
    def __init__(self):
        self.cache_dir = Path(os.getenv("CACHE_DIR", ".cache/sarif"))
        if not self.cache_dir.exists():
            self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.joblib_dir = self.cache_dir / "joblib"
        if not self.joblib_dir.exists():
            self.joblib_dir.mkdir(exist_ok=True)

        self.memory = joblib.Memory(location=self.joblib_dir.as_posix(), verbose=0)

    def clear(self):
        self.memory.clear()


@singleton
class SarifServerManager:
    def __init__(self, joern_kwargs: dict = {}):
        from sarif.tools.joern.server import JoernServer

        self.joern_server = JoernServer(
            cpg_path=SarifEnv(check_initialized=True).joern_cpg_path, **joern_kwargs
        )


DEBUG_MODE = Literal["debug", "release"]
ENV_MODE = Literal["local", "docker", "crs"]

CONFIG_NAME = Literal["default", "loose", "strict"]


@singleton
class SarifConfigManager:
    def __init__(self, config_name: CONFIG_NAME = "default"):
        with resources.path(
            "sarif.static.config", f"{config_name}.yaml"
        ) as config_path:
            with open(config_path, "r") as f:
                config_data = yaml.safe_load(f)
                self.config = SarifConfig(**config_data)

        self.config_name = config_name


# Environment storage
@singleton
class SarifEnv:
    def __init__(
        self,
        cp: CP,
        env_mode: ENV_MODE = "local",
        debug_mode: DEBUG_MODE = "debug",
    ):
        self.cp = cp
        self.env_mode = env_mode
        self.debug_mode = debug_mode

        # Default paths
        self.src_dir: Path | None = None
        self.out_dir: Path | None = None
        self.build_dir: Path | None = None
        self.class_dir: Path | None = None
        self.compiled_src_dir: Path | None = None
        # DB paths
        self.codeql_db_path: Path | None = None
        self.joern_cpg_path: Path | None = None
        self.svf_dot_path: Path | None = None
        self.sootup_dot_path: Path | None = None
        self.cpmeta_paths: list[Path] = []
        self.cpmeta_dicts: list[dict] = []
        # Seeds from other crs
        self.seed_dir: Path | None = None
        # Coverage save path
        self.coverage_dir: Path | None = None
        match self.env_mode:
            case "local":
                self._init_local_env()
            case "docker":
                self._init_docker_env()
            case "crs":
                self._init_crs_env()
            case _:
                raise ValueError(f"Invalid environment mode: {self.env_mode}")

        match self.debug_mode:
            case "debug":
                self._init_debug_env()
            case "release":
                self._init_release_env()
            case _:
                raise ValueError(f"Invalid debug mode: {self.debug_mode}")

    def _init_local_env(self):
        self.out_dir = Path(os.getenv("OUT_DIR")) / self.cp.name

        if self.cp.language == "java":
            self.src_dir = Path(os.getenv("SRC_DIR")) / self.cp.name / "src" / "src"
        else:
            self.src_dir = Path(os.getenv("SRC_DIR")) / self.cp.name / "src"
        # TODO: set up for java
        if self.cp.language == "java":
            # ! FIXME: this is a hack to get the class directory
            # self.class_dir = Path(os.getenv("CLASS_DIR")) / cp.name
            ossfuzz_dir = Path(os.getenv("OSS_FUZZ_DIR"))
            self.project_full_name = f"aixcc/{self.cp.language if self.cp.language != 'java' else 'jvm'}/{self.cp.name}"
            self.class_dir = (
                ossfuzz_dir / "build" / "out" / self.project_full_name / "jars"
            )

        self.build_dir = Path(os.getenv("BUILD_DIR"))

        self.joern_cpg_path = self.build_dir / "joern-cpg" / f"{self.cp.name}.cpg.bin"
        self.codeql_db_path = self.build_dir / "codeql-db" / self.cp.name

        # TODO: might be change directory
        self.svf_dot_path = self.out_dir / "SVF"
        self.sootup_dot_path = self.out_dir / "sootup"
        # self.cp.update_harness_path(self.src_dir)
        # self.cp.update_harness_path_from_codeql(self.codeql_db_path)

    def _init_docker_env(self):
        ossfuzz_dir = Path(os.getenv("OSS_FUZZ_DIR"))
        self.project_full_name = f"aixcc/{self.cp.language if self.cp.language != 'java' else 'jvm'}/{self.cp.name}"

        self.out_dir = ossfuzz_dir / "build" / "out" / self.project_full_name
        # TODO: src is not available in docker mode. just set it as project root
        self.src_dir = ossfuzz_dir / "projects" / self.project_full_name
        self.build_dir = Path(
            os.getenv(
                "BUILD_DIR",
                f"{ossfuzz_dir}/build/out/{self.project_full_name}",
            )
        )
        if self.cp.language == "java":
            self.class_dir = (
                ossfuzz_dir / "build" / "out" / self.project_full_name / "jars"
            )

        self.joern_cpg_path = self.build_dir / "joern-cpg" / f"{self.cp.name}.cpg.bin"
        self.codeql_db_path = self.build_dir / "codeql-db" / self.cp.name

        # TODO: codeql-db is not available in docker mode.
        # self.codeql_db_dir = self.build_dir / "codeql-db" / cp.name

    def _init_crs_env(self):
        # Default paths
        self.src_dir = Path(os.getenv("SRC_DIR", "/src"))
        self.out_dir = Path(os.getenv("OUT_DIR", "/out"))
        self.build_dir = Path(os.getenv("BUILD_DIR", "/build"))
        self.compiled_src_dir = self.build_dir / "compiled_src"
        # DB paths
        self.codeql_db_path = self.build_dir / "codeql"
        self.joern_cpg_path = self.build_dir / "joern" / "cpg.bin"
        self.svf_dot_path = self.build_dir / "SVF"
        self.sootup_dot_path = self.build_dir / "sootup"
        self.reachability_dir = self.out_dir / "reachability"

        # Shared directories
        self.corpus_shared_dir = Path(os.getenv("CORPUS_SHARED_DIR"))
        self.coverage_shared_dir = Path(os.getenv("COVERAGE_SHARED_DIR"))
        self.reachability_shared_dir = Path(os.getenv("REACHABILITY_SHARED_DIR"))

        logger.info(f"SarifEnv: {vars(self)}")

    def _init_debug_env(self):
        pass

    def _init_release_env(self):
        pass


def init_phoenix():
    register(
        project_name="sarif",
        auto_instrument=True,
        endpoint=f"{os.getenv('PHOENIX_COLLECTOR_ENDPOINT')}/v1/traces",
    )


def init_context(
    cp: CP,
    env_mode: ENV_MODE = "local",
    debug_mode: DEBUG_MODE = "debug",
    src_dir: Path | None = None,
    out_dir: Path | None = None,
    log_level: int = logging.DEBUG,
    llm_on: bool = False,
    temperature_setting: TEMPERATURE_SETTING = "default",
    config_name: CONFIG_NAME = "default",
    force_new_instance: bool = True,
):
    load_dotenv(override=True)
    init_logger(log_level)

    sarif_env = SarifEnv(
        cp=cp,
        env_mode=env_mode,
        debug_mode=debug_mode,
        force_new_instance=force_new_instance,
    )

    if src_dir is None:
        src_dir = sarif_env.src_dir

    if out_dir is None:
        out_dir = sarif_env.out_dir

    SarifConfigManager(config_name=config_name)

    SarifCacheManager()

    SarifCodeContextManager(
        src_dir=src_dir,
        out_dir=out_dir,
        force_new_instance=force_new_instance,
    )

    if llm_on:
        init_phoenix()

        SarifLLMManager(
            temperature_setting=temperature_setting,
            force_new_instance=force_new_instance,
        )
