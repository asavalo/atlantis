import json
import os
from pathlib import Path
from typing import Literal

import click
from dotenv import load_dotenv

from sarif.dataset.modification import DataAugmentation, SinkLocation
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as AIxCCSarif,
)
, init_logger
from sarif.utils.sarif import deduplicate_sarif as deduplicate_sarif_utils
from sarif.utils.sarif import split_sarif


@click.group()
def cli():
    load_dotenv()
    init_logger()


@cli.command()
@click.argument("sarif_dir_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--tool_name",
    type=click.Choice(["codeql", "snyk", "semgrep", "llm-poc-gen", "all"]),
    default=None,
)
@click.option("--out_dir", type=click.Path(exists=True, path_type=Path), default=None)
def deduplicate_sarif(
    sarif_dir_path: Path,
    tool_name: Literal["codeql", "snyk", "semgrep", "llm-poc-gen", "all"] | None,
    out_dir: Path | None = None,
) -> None:
    if out_dir is None:
        out_dir = sarif_dir_path

    if tool_name is None:
        tool_name = "all"

    from loguru import logger

    logger.debug(f"Deduplicating SARIF files in {sarif_dir_path}")

    if tool_name != "all":
        glob_str = f"{tool_name}*.sarif"
    else:
        glob_str = "*.sarif"

    sarif_files = list(sarif_dir_path.glob(glob_str))
    if len(sarif_files) == 0:
        logger.warning(f"No SARIF files found in {sarif_dir_path}")
        return
    sarif_models = []

    for file in sarif_files:
        try:
            sarif_models.append(AIxCCSarif.model_validate(json.loads(file.read_text())))
        except Exception as e:
            logger.warning(f"Error validating SARIF file {file}: {e}")
            continue

    # sarif_models = [
    #     AIxCCSarif.model_validate_json(file.read_text()) for file in sarif_files
    # ]

    dedup_sarif_files = deduplicate_sarif_utils(sarif_models)

    # sarif_tool_names = sarif_files[0].stem.split("_")[0]

    # Remove the original sarif files
    if out_dir == sarif_dir_path:
        for file in sarif_files:
            file.unlink()

    for i, sarif_model in enumerate(dedup_sarif_files):
        output_path = out_dir / f"{tool_name}_{i}.sarif"

        with open(output_path, "w") as f:
            json.dump(
                sarif_model.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_defaults=True,
                    exclude_none=True,
                ),
                f,
                indent=4,
            )

    logger.debug(
        f"Saved {len(dedup_sarif_files)} deduplicated SARIF files to {out_dir}"
    )


@cli.command()
@click.argument("sarif_path", type=click.Path(exists=True, path_type=Path))
@click.argument("out_dir", type=click.Path(exists=True, path_type=Path))
def filter_and_split_sarif(sarif_path: Path, out_dir: Path) -> None:
    from loguru import logger

    logger.debug(f"Filtering and splitting SARIF file {sarif_path}")

    sarif = json.loads(sarif_path.read_text())
    # sarif = AIxCCSarif.model_validate_json(sarif_path.read_text())

    spllited_sarifs = split_sarif(sarif)

    if not out_dir.exists():
        raise FileNotFoundError(f"Directory {out_dir.as_posix()} does not exist")

    for i, sarif in enumerate(spllited_sarifs):
        output_path = out_dir / f"{sarif_path.stem}_{i}.sarif"

        with open(output_path, "w") as f:
            json.dump(
                sarif.model_dump(
                    mode="json", by_alias=True, exclude_defaults=True, exclude_none=True
                ),
                f,
                indent=4,
            )

    logger.debug(f"Saved {len(spllited_sarifs)} SARIF files to {out_dir}")


@cli.command()
@click.argument("repo_name", type=str)
@click.argument("db_path", type=click.Path(exists=True, path_type=Path))
@click.argument("language", type=click.Choice(["c", "java"]))
@click.argument("cwe_id", type=str)
def get_sink_candidates(
    repo_name: str, db_path: Path, language: Literal["c", "java"], cwe_id: str
) -> list[SinkLocation]:
    from loguru import logger

    logger.debug(
        f"Getting sink candidates for {repo_name} with {language} and {cwe_id}"
    )

    candidates = DataAugmentation(
        db_path=db_path,
        lang=language,
        cwe_id=cwe_id,
    )._get_sink_candidates()

    output = (
        Path(os.getenv("DATA_DIR"))
        / language
        / "out"
        / "dataset"
        / f"{repo_name}_{cwe_id}_sink_candidates.json"
    )
    with open(output, "w") as f:
        res_json = [candidate.model_dump() for candidate in candidates]
        json.dump(res_json, f, indent=4)

    logger.debug(f"Saved sink candidates to {output}")

    return candidates


if __name__ == "__main__":
    cli()
