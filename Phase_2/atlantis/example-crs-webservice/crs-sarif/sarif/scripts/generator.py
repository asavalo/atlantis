import os
from pathlib import Path
from typing import Literal

import click
from dotenv import load_dotenv
from loguru import logger
from rich import print_json

from sarif.context import init_context
from sarif.generator import (
    generate_sarif,
    generate_sarif_from_patch,
    save_sarif_to_file,
)
from sarif.generator.c import generate_sarif_custom_c, generate_sarif_ossfuzz_c
from sarif.llm.graph.sarif import OutputState as FinalState
from sarif.llm.graph.sarif import generate_sarif_graph
from sarif.llm.graph.vuln_info import InputState as InitialState


@click.group()
def cli():
    load_dotenv()


@cli.command()
@click.argument("vuln_id", type=str)
@click.argument("crash_log_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--patch_diff_path", type=click.Path(exists=True, path_type=Path), default=None
)
@click.option("--language", type=click.Choice(["c", "java"]), default="c")
def run_llm(
    vuln_id: str,
    crash_log_path: Path,
    patch_diff_path: Path | None = None,
    language: Literal["c", "java"] = "c",
):
    load_dotenv()

    with open(crash_log_path, "r") as f:
        sanitizer_output = f.read()

    if patch_diff_path is not None:
        with open(patch_diff_path, "r") as f:
            patch_diff = f.read()
    else:
        patch_diff = ""

    # make out dir
    base_out_dir = Path(os.environ.get("DATA_DIR")) / language / "out"
    out_dir = base_out_dir / vuln_id
    if not out_dir.exists():
        out_dir.mkdir(parents=True)

    init_context(src_dir="", out_dir=str(out_dir.resolve()))

    input_state = InitialState(
        package_language=language,
        package_name=vuln_id.split("_")[0],
        package_location="",
        vuln_id=vuln_id,
        sanitizer_output=sanitizer_output,
        patch_diff=patch_diff,
        experiment_name="TEST",
    )

    sarif_graph = generate_sarif_graph()

    output = sarif_graph.invoke(input_state)
    output_state = FinalState(**output)

    print_json(output_state.model_dump_json())


@cli.command()
@click.argument("crash_log_path", type=click.Path(exists=True, path_type=Path))
@click.argument("output_file", type=click.Path(path_type=Path))
@click.argument("mode", type=click.Choice(["custom", "ossfuzz"]), default="custom")
@click.option("--language", type=click.Choice(["c", "java"]), default=None)
@click.option("--llm_on", type=bool, default=False)
@click.option("--validate", type=bool, default=False)
@click.option(
    "--patch_diff_path", type=click.Path(exists=True, path_type=Path), default=None
)
@click.option("--target_name", type=str, default=None)
def run_one(
    crash_log_path: Path,
    output_file: Path,
    mode: Literal["custom", "ossfuzz"] = "custom",
    language: Literal["c", "java"] | None = None,
    llm_on: bool = False,
    validate: bool = False,
    patch_diff_path: Path | None = None,
    target_name: str | None = None,
):
    try:
        print(f"[+] Processing {crash_log_path}...")
        report = generate_sarif(
            crash_log_path,
            patch_diff_path,
            language,
            mode,
            llm_on,
            validate,
            target_name,
        )
        print(f"[+] Saving to {output_file}...")
        save_sarif_to_file(report, output_file)
        print(f"[+] Done processing {crash_log_path}")
    except Exception as e:
        print(f"[-] Error processing {crash_log_path}: {e}")
        raise e


@cli.command()
# @click.argument(
#     "input_dir",
#     type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
# )
@click.argument(
    "oss-fuzz-dir", type=click.Path(exists=True, file_okay=False, dir_okay=True)
)
@click.argument(
    "output_dir", type=click.Path(file_okay=False, dir_okay=True, path_type=Path)
)
@click.argument("mode", type=click.Choice(["custom", "ossfuzz"]), default="custom")
@click.option("--language", type=click.Choice(["c", "java"]), default=None)
@click.option("--llm_on", type=bool, default=False)
@click.option("--validate", type=bool, default=False)
@click.pass_context
def run_all(
    ctx,
    oss_fuzz_dir: Path,
    output_dir: Path,
    mode: Literal["custom", "ossfuzz"] = "custom",
    language: Literal["c", "java"] | None = None,
    llm_on: bool = False,
    validate: bool = False,
):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    if language == "java":
        oss_fuzz_lang = "jvm"
    else:
        oss_fuzz_lang = "c"

    oss_fuzz_projects_dir = Path(oss_fuzz_dir) / "projects" / "aixcc" / oss_fuzz_lang
    oss_fuzz_projects = os.listdir(oss_fuzz_projects_dir)

    for project in oss_fuzz_projects:
        project_dir = oss_fuzz_projects_dir / project
        crash_log_dir = project_dir / ".aixcc" / "crash_logs"
        if not crash_log_dir.exists():
            logger.warning(f"No crash logs found for {project}")
            continue

        for harness_name in os.listdir(crash_log_dir):
            harness_dir = crash_log_dir / harness_name
            for crash_log_name in os.listdir(harness_dir):
                cpv_id = crash_log_name.split(".")[0]

                crash_log_path = harness_dir / f"{cpv_id}.log"
                output_file = (
                    output_dir
                    / oss_fuzz_lang
                    / f"{project}-{harness_name}-{cpv_id}.sarif"
                )

                output_file.parent.mkdir(parents=True, exist_ok=True)

                try:
                    ctx.invoke(
                        run_one,
                        crash_log_path=crash_log_path,
                        output_file=output_file,
                        mode=mode,
                        language=language,
                        llm_on=llm_on,
                        validate=validate,
                    )
                except Exception as e:
                    print(f"[-] Error processing {crash_log_name}: {e}")
                else:
                    print(f"[+] Done processing {crash_log_name}")

    print(f"[+] Done processing all {oss_fuzz_projects}")

    # for crash_log_name in os.listdir(input_dir / "crash_log"):
    #     if crash_log_name.endswith(".log"):
    #         target_name = "_".join(crash_log_name.split("_")[1:-2])
    #         cpv_id = crash_log_name.split(".")[0]

    #         if llm_on:
    #             cpv_id = f"{cpv_id}_llm"

    #         crash_log_path = input_dir / "crash_log" / f"{cpv_id}.log"
    #         # patch_diff_path = input_dir / "sound_patch" / f"{cpv_id}.diff"
    #         patch_diff_path = input_dir / "dev_patch" / f"{cpv_id}.diff"
    #         if mode == "ossfuzz":
    #             output_file = output_dir / "sarif" / f"{cpv_id}_ossfuzz.sarif"
    #         else:
    #             output_file = output_dir / "sarif" / f"{cpv_id}.sarif"

    #         try:
    #             ctx.invoke(
    #                 run_one,
    #                 crash_log_path=crash_log_path,
    #                 output_file=output_file,
    #                 mode=mode,
    #                 language=language,
    #                 llm_on=llm_on,
    #                 validate=validate,
    #                 patch_diff_path=patch_diff_path,
    #                 target_name=target_name,
    #             )
    #         except Exception as e:
    #             print(f"[-] Error processing {crash_log_name}: {e}")
    #         else:
    #             print(f"[+] Done processing {crash_log_name}")


@cli.command()
@click.argument(
    "input_dir", type=click.Path(exists=True, file_okay=False, dir_okay=True)
)
def compare_two_mode(input_dir):
    crash_log_dir = os.path.join(input_dir, "crash_log")

    for filename in os.listdir(crash_log_dir):
        if filename.endswith(".log"):
            print(f"[+] Processing {filename}...")

            target_name = "_".join(filename.split("_")[1:-2])

            crash_log_path = os.path.join(input_dir, filename)

            try:
                report_custom = generate_sarif_custom_c(crash_log_path).model_dump()
            except Exception as e:
                print(f"[-] Error generating {filename} in custom mode: {e}")
                report_custom = None
            try:
                report_ossfuzz = generate_sarif_ossfuzz_c(crash_log_path, target_name)
            except Exception as e:
                print(f"[-] Error generating {filename} in ossfuzz mode: {e}")
                report_ossfuzz = None

            # Compare the specific dictionary entries
            c_uri = c_index = c_startLine = c_startColumn = o_uri = o_index = (
                o_startLine
            ) = o_startColumn = None

            try:
                custom_location = report_custom["runs"][0]["results"][0]["locations"][
                    0
                ]["physical_location"]["artifact_location"]
                custom_region = report_custom["runs"][0]["results"][0]["locations"][0][
                    "physical_location"
                ]["region"]
                c_uri = custom_location["uri"]
                c_index = custom_location["index"]
                c_startLine = custom_region["start_line"]
                c_startColumn = custom_region["start_column"]
            except Exception as e:
                print(f"[-] Error parsing {filename} in custom mode: {e}")

            try:
                ossfuzz_location = report_ossfuzz["runs"][0]["results"][0]["locations"][
                    0
                ]["physicalLocation"]["artifactLocation"]
                ossfuzz_region = report_ossfuzz["runs"][0]["results"][0]["locations"][
                    0
                ]["physicalLocation"]["region"]
                o_uri = ossfuzz_location["uri"]
                o_index = ossfuzz_location["index"]
                o_startLine = ossfuzz_region["startLine"]
                o_startColumn = ossfuzz_region["startColumn"]
            except Exception as e:
                print(f"[-] Error parsing {filename} in ossfuzz mode: {e}")

            if (
                c_uri != o_uri
                or c_index != o_index
                or c_startLine != o_startLine
                or c_startColumn != o_startColumn
            ):
                print(f"[-] Mismatch for {filename}")
                print(f"custom: {c_uri}, {c_index}, {c_startLine}, {c_startColumn}")
                print(f"ossfuzz: {o_uri}, {o_index}, {o_startLine}, {o_startColumn}")
            else:
                print(f"[+] Match for {filename}")

            print(f"[+] Done processing {filename}")


@cli.command()
@click.argument("patch_diff_path", type=click.Path(exists=True, path_type=Path))
@click.argument("output_file", type=click.Path(path_type=Path))
def run_with_patch(
    patch_diff_path: Path,
    output_file: Path,
):
    """Generates a SARIF report from a patch diff file."""
    try:
        print(f"[+] Processing patch diff {patch_diff_path}...")
        # Call the new function from the generator module
        report = generate_sarif_from_patch(patch_diff_path)
        print(f"[+] Saving SARIF report to {output_file}...")
        # Ensure output directory exists
        output_file.parent.mkdir(parents=True, exist_ok=True)
        save_sarif_to_file(report, output_file)
        print(f"[+] Done processing patch diff {patch_diff_path}")
    except Exception as e:
        print(f"[-] Error processing patch diff {patch_diff_path}: {e}")
        # Optionally re-raise the exception if needed
        # raise e


if __name__ == "__main__":
    cli()
