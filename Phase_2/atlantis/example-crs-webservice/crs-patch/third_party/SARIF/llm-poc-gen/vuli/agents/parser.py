import json
import logging
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from langchain_core.output_parsers.base import BaseOutputParser
from vuli.common.setting import Setting
from vuli.struct import LLMParseException

logger = logging.getLogger("vuli")

class JsonParser(BaseOutputParser[list]):
    def parse(self, text: str) -> str:
        try:
            jsons = [
                json.loads(x) for x in re.findall(r"```json\n(.*?)```", text, re.DOTALL)
            ]
            if len(jsons) == 0:
                raise LLMParseException()
            return jsons[0]
        except Exception as e:
            logger.debug(e)
            error_message = f"""Your response does not contain content in JSON format, so the following error occurred while parsing:
ERROR:
{type(e).__name__}: {e}
PARSE CODE:
jsons = [
    json.loads(x) for x in re.findall(r"```json\n(.*?)```", text, re.DOTALL)
]
Please carefully review your previous response to ensure that no parsing errors occur.
After reviewing, please regenerate your response to address the issues from your previous answer.
"""
            raise LLMParseException(error_message)


class PythonParser(BaseOutputParser[dict]):
    def parse(self, text: str) -> list[dict]:
        try:
            scripts: list[str] = re.findall(r"```python\n(.*?)```", text, re.DOTALL)
            result: list[tuple[str, bytes]] = [(x, self.__run_python(x)) for x in scripts]
            result: list[dict] = [
                {"blob": blob, "script": script} for script, blob in result if len(blob) > 0
            ]
            if len(result) == 0:
                raise LLMParseException(
                    "You MUST include python script in your answer. Put python script in ```python\n``` format."
                )
        except Exception as e:
            logger.debug(e)
            raise LLMParseException(e)
    
        return result

    def __run_python(self, script: str) -> bytes:
        try:
            script_file = tempfile.NamedTemporaryFile(
                dir=Setting().tmp_dir, mode="wt", suffix=".py"
            )
            script_file.write(script)
            script_file.flush()

            output_file = tempfile.NamedTemporaryFile(dir=Setting().tmp_dir)
            cmd = [sys.executable, script_file.name, output_file.name]
            subprocess.run(cmd, timeout=10, check=True, text=True, capture_output=True)
            with Path(output_file.name).open("rb") as f:
                blob: bytes = f.read()
            return blob
        except Exception as e:
            
            error_message = f"""I encountered an error while executing the Python script generated from your response.
Analyze the error using the provided stack trace and fix the issue in the previously generated script before responding again.
The corrected script must follow the Python format used in your previous response, and be enclosed in ```python\n``` format.

<STACKTRACE>
{e.stderr}
"""
            raise LLMParseException(error_message)
