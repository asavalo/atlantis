import asyncio
import logging
import os
import sys
from argparse import ArgumentParser
from pathlib import Path
from typing import Optional

import coloredlogs
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from vuli.common.setting import Setting, Storage
from vuli.cp import CP
from vuli.dev import Dev
from vuli.model_manager import ModelManager
from vuli.runner import CRS, Runner, StandAlone


def process_command_line_options():
    parser = ArgumentParser(description="llm-poc-gen")
    sub_parsers = parser.add_subparsers(dest="type")
    crs_parser = sub_parsers.add_parser("crs", help="Run inside CRS-java")

    parser.add_argument(
        "--cp_meta",
        required=True,
        type=str,
        help="CP metadata file (required)",
    )
    parser.add_argument("--dev", action="store_true", help="Dev Mode")
    parser.add_argument(
        "--harnesses",
        type=str,
        help="This option allows you to specify the IDs of the harnesses you want to test. If you want to test multiple harnesses, you can list their IDs separated by commas. If this option is not provided, the test will be performed on all available harnesses.",
    )
    parser.add_argument("--jazzer", required=False, type=str, help="The path to jazzer")
    parser.add_argument(
        "--joern_dir",
        required=True,
        type=str,
        help="The path to the Joern directory",
    )
    parser.add_argument(
        "--log_level",
        choices=["DEBUG", "INFO", "WARN", "ERROR"],
        default="INFO",
        type=str,
        help="Log Level[DEBUG/INFO/WARN/ERROR](default: INFO)",
    )
    parser.add_argument(
        "--model_cache", type=str, help="The path to cache for model interaction"
    )
    parser.add_argument(
        "--workers",
        default=1,
        type=int,
        help="The number of workers for blob generation",
    )
    parser.add_argument(
        "--output_dir",
        default=str(Path("output").absolute()),
        type=str,
        help="The path to the output directory",
    )
    parser.add_argument(
        "--sarif",
        type=str,
        help="The path to sarif report file",
    )
    parser.add_argument(
        "--shared_dir",
        required=True,
        type=str,
        help="The path to shared directory",
    )
    crs_parser.add_argument("--period", type=int, default=5, help="Polling Period")
    crs_parser.add_argument("--port", type=int, default=10100, help="Server Port")
    return parser.parse_args()


def initialize_system(
    cp_meta: Path,
    jazzer: Optional[Path],
    joern_dir: Path,
    model_cache: Optional[Path],
    output_dir: Path,
    dev: bool,
    harnesses: list[str],
    log_level: str,
    sarif_path: Path,
    shared_dir: Path,
) -> None:
    initialize_logger(log_level)

    root_dir: Path = Path(__file__).parent.parent.absolute()
    Setting().load(jazzer, joern_dir, output_dir, root_dir, dev, sarif_path,shared_dir)
    Storage().set_path(Setting().blackboard_path)
    CP().load(cp_meta, harnesses)
    Dev().load(Setting().root_dir / "dev" / "cpv.toml")

    api_key: str = os.getenv("LITELLM_KEY", "tmp")
    base_url: str = os.getenv(
        "AIXCC_LITELLM_HOSTNAME",
        "https://litellm-proxy-153298433405.us-east1.run.app",
    )
    temperature: float = 1.0
    if model_cache is not None:
        ModelManager().set_cache(model_cache)
    ModelManager().set_max_retries(3)
    ModelManager().set_worker(1)

    model_name_env = os.getenv("MODEL_NAME", "")
    if model_name_env == "o1":
        ModelManager().add_model(
            lambda input, output: input * 0.000015 + output * 0.00006,
            "o1",
            ChatOpenAI(
                api_key=api_key,
                base_url=base_url,
                model="o1",
                temperature=temperature
            ),
        )
    elif model_name_env == "gemini":
        ModelManager().add_model(
            lambda input, output: (
                input * 0.0000125 + output * 0.000075
                if input > 200000
                else input * 0.00000625 + output * 0.00005
            ),
            "gemini-2.5-pro",
            ChatOpenAI(
                api_key=api_key,
                base_url=base_url,
                model="gemini-2.5-pro-preview-03-25",
                temperature=temperature
            ),
        )
    elif model_name_env == "claude":
        ModelManager().add_model(
            lambda input, output: input * 0.000003 + output * 0.000015,
            "claude-3.7-sonnet",
            ChatAnthropic(
                api_key=api_key,
                base_url=base_url,
                model="claude-3-7-sonnet-20250219",
                temperature=temperature,
                max_tokens=128000,
                thinking={"type": "enabled", "budget_tokens": 127999},
                extra_headers={"anthropic-beta": "output-128k-2025-02-19"}
            ),
        )
    else:
        ModelManager().add_model(
            lambda input, output: input * 0.0000025 + output * 0.00001,
            "gpt-4o",
            ChatOpenAI(
                api_key=api_key, base_url=base_url, model="gpt-4o", temperature=temperature
            ),
        )
        ModelManager().add_model(
            lambda input, output: input * 0.000003 + output * 0.000015,
            "claude-3.7-sonnet",
            ChatAnthropic(
                api_key=api_key,
                base_url=base_url,
                model="claude-3-7-sonnet-20250219",
                temperature=temperature,
                max_tokens=12800,
            ),
        )
        ModelManager().add_model(
            lambda input, output: (
                input * 0.00000125 + output * 0.000005
                if input > 128000
                else input * 0.0000025 + output * 0.00001
            ),
            "gemini-1.5-pro",
            ChatOpenAI(
                api_key=api_key,
                base_url=base_url,
                model="gemini-1.5-pro",
                temperature=temperature,
            ),
        )


def initialize_logger(log_level: str) -> None:
    level = getattr(logging, log_level, None)
    if level is None:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="[%(asctime)s] [%(name)s] (%(levelname)s) %(message)s",
        handlers=[logging.StreamHandler()],
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    coloredlogs.install(
        level=log_level, fmt="[%(asctime)s] [%(name)s] (%(levelname)s) %(message)s"
    )
    logging.getLogger("anthropic._base_client").setLevel(logging.CRITICAL)
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)
    logging.getLogger("openai._base_client").setLevel(logging.CRITICAL)
    logging.getLogger("httpcore.connection").setLevel(logging.CRITICAL)
    logging.getLogger("httpcore.http11").setLevel(logging.CRITICAL)
    logging.getLogger("httpx").setLevel(logging.CRITICAL)
    logging.getLogger("urllib3.connection").setLevel(logging.CRITICAL)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.CRITICAL)


def main():
    args = process_command_line_options()

    cp_meta: Path = Path(args.cp_meta).absolute()
    jazzer: Path = Path(args.jazzer).absolute() if args.jazzer else None
    joern_dir: Path = Path(args.joern_dir).absolute()
    model_cache: Optional[Path] = (
        Path(args.model_cache).absolute() if args.model_cache else None
    )
    output_dir: Path = Path(args.output_dir).absolute()
    dev: bool = args.dev
    harnesses: list[str] = (
        [x.strip() for x in args.harnesses.split(",")] if args.harnesses else []
    )
    log_level: str = args.log_level
    sarif_path: str = Path(args.sarif).absolute()
    shared_dir: Path = Path(args.shared_dir).absolute()
    initialize_system(
        cp_meta, jazzer, joern_dir, model_cache, output_dir, dev, harnesses, log_level, sarif_path, shared_dir
    )

    runner: Runner = None
    if args.type == "crs":
        from libCRS.otel import install_otel_logger

        install_otel_logger(action_name="crs-java:llm-poc-gen")
        period: int = args.period
        port: int = args.port
        runner = CRS(period, port, args.workers)
    else:
        runner = StandAlone(args.workers)
    asyncio.run(runner.run())


if __name__ == "__main__":
    sys.exit(main())
