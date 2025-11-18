import json
from importlib.resources import files
from pathlib import Path

from jsonschema import validate
from jsonschema.exceptions import ValidationError
from loguru import logger
from pydantic import BaseModel

from sarif.utils.cmd import BaseCommander


class FormatValidateRes(BaseModel):
    is_valid: bool
    errors: list[str]
    warnings: list[str]


def validate_format_jsonschema(sarif_path: Path) -> FormatValidateRes:
    with open(sarif_path, "r", encoding="utf-8") as file:
        sarif_data = json.load(file)

    aixcc_schema_path = files("sarif").joinpath("static/sarif-schema-v0.3.json")

    with open(aixcc_schema_path, "r", encoding="utf-8") as file:
        schema = json.load(file)

    try:
        validate(instance=sarif_data, schema=schema)
        logger.info("valid SARIF")

        return FormatValidateRes(is_valid=True, errors=[], warnings=[])
    except ValidationError as e:
        logger.error(f"Error: {e.message}")

        return FormatValidateRes(is_valid=False, errors=[e.message], warnings=[])
    except json.JSONDecodeError as e:
        logger.error("JSON decoding error")

        return FormatValidateRes(is_valid=False, errors=[e.msg], warnings=[])


def validate_format_multitool(sarif_path: Path) -> FormatValidateRes:
    # validate sarif report using sarif.multitool (https://www.npmjs.com/package/@microsoft/sarif-multitool)
    NUM_THREADS = 10

    logger.info(f"Validating SARIF report: {sarif_path}")

    aixcc_schema_path = files("sarif").joinpath("static/sarif-schema-v0.3.json")

    runner = BaseCommander()
    validate_cmd = f"npx @microsoft/sarif-multitool validate {sarif_path} --json-schema {aixcc_schema_path} --threads {NUM_THREADS}"
    result = runner.run(validate_cmd, pipe=True)

    errors = []
    warnings = []
    for line in result.stdout.splitlines():
        if "error" in line.lower():
            errors.append(line)
        if "warning" in line.lower():
            warnings.append(line)

    for error in errors:
        logger.error(error)
    for warning in warnings:
        logger.warning(warning)

    is_valid = len(errors) == 0

    return FormatValidateRes(is_valid=is_valid, errors=errors, warnings=warnings)
