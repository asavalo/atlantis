import json
import logging
import re
from pathlib import Path

from langchain_core.messages import BaseMessage
from langchain_core.messages.system import SystemMessage
from unidiff import Hunk, PatchedFile, PatchSet
from vuli.model_manager import ModelManager
from vuli.struct import LLMParseException


class DeltaParser:
    def __init__(self):
        self._logger = logging.getLogger("DeltaParser")

    def parse(self, text: str) -> dict:
        jsons = [x for x in re.findall(r"```json\n(.*?)```", text, re.DOTALL)]
        if len(jsons) == 0:
            self._logger.debug(f"LLM Answer: {text}")
            raise LLMParseException(
                "No json included. Please include ```json\n``` for answer"
            )
        if len(jsons) > 1:
            self._logger.debug(f"LLM Answer: {text}")
            raise LLMParseException(
                "More than one json included. PLease include only one json for answer"
            )

        try:
            root: dict = json.loads(jsons[0])
        except json.JSONDecodeError as e:
            self._logger.debug(f"LLM Answer: {jsons[0]}")
            raise LLMParseException(
                f"Invalid json format. Please answer json again. Below is an error message while parsing the json.\n{e}"
            )

        if not isinstance(root, list):
            self._logger.debug(f"Json: {root}")
            raise LLMParseException(
                "Invalid json format. Root element must be list. Please answer json again."
            )

        necessary_keys: set[str] = set(
            {"hunk_number", "line_number_in_hunk", "vulnerability_type"}
        )
        for object in root:
            missing_keys: set[str] = necessary_keys - set(object.keys())
            if len(missing_keys) > 0:
                raise LLMParseException(
                    f"Missing keys ({",".join(missing_keys)}) in this object {object}. Please answer json again."
                )
        return root


class Delta:
    def __init__(self):
        self._logger = logging.getLogger("Delta")

    def get_sinks(self, path: Path) -> list[dict]:
        hunks: list[tuple[PatchedFile, Hunk]] = self._create_hunk_list(path)
        hunk_message: str = self._create_hunk_message(hunks)
        inferred_sinks: list[dict] = self._infer_sinks(hunk_message)
        sinks: list[dict] = self._create_outputs(inferred_sinks, hunks)
        return sinks

    def _create_hunk_list(self, path: Path) -> list[tuple[PatchedFile, Hunk]]:
        patch = PatchSet.from_filename(str(path))
        hunks: list[tuple[PatchedFile, Hunk]] = [(x, y) for x in patch for y in x]
        return hunks

    def _create_hunk_message(self, hunks: list[tuple[PatchedFile, Hunk]]) -> str:
        hunk_msgs: list[str] = []
        for idx, hunk in enumerate(hunks):
            lines: list[str] = str(hunk[1]).split("\n")
            line_number_width: int = len(lines)
            lines: list[str] = [
                f"{str(index + 1).rjust(line_number_width)}   {line}"
                for index, line in enumerate(lines)
            ]
            hunk_msgs.append(f"Hunk #{idx}\n{"\n".join(lines)}")
        return "\n\n".join(hunk_msgs)

    def _infer_sinks(self, hunk_message: str) -> list[dict]:
        messages: list[BaseMessage] = [
            SystemMessage(
                content=f"""
Find any introduced vulnerabilities in the given diff file. Please answer is as below format.
Line number should indicate the line in hunk where vulnerability will be triggered.
```json
[
    {{"hunk_number": xx, "line_number_in_hunk": yy, "vulnerability_type": "", "related_code": "xxx"}},
    ...
]
```
<DIFF>
{hunk_message}
"""
            )
        ]
        result: list[dict] = ModelManager().invoke(messages, "gpt-4o", DeltaParser())
        return result

    def _create_outputs(
        self, inferred_sinks: list[dict], hunks: list[tuple[PatchedFile, Hunk]]
    ) -> list[dict]:
        result: list[dict] = []
        for data in inferred_sinks:
            output: dict = self._create_output(hunks, data)
            if output.keys() == 0:
                self._logger.warning(f"Invalid Format: Skipped ({data})")
                continue
            result.append(output)
        return result

    def _create_output(self, hunks: list[tuple[PatchedFile, Hunk]], src: dict) -> dict:
        necessary_keys: set[str] = set(
            {"hunk_number", "line_number_in_hunk", "vulnerability_type"}
        )
        if len(necessary_keys - set(src.keys())) > 0:
            return {}

        hunk_number: int = src["hunk_number"]
        hunk_line_number: int = src["line_number_in_hunk"]
        vulnerability_type: str = src["vulnerability_type"]
        file_path: str = hunks[hunk_number][0].target_file
        file_path: str = file_path[file_path.find("/") + 1 :]
        return {
            "file_path": file_path,
            "line": self._create_code_line(hunks[hunk_number][1], hunk_line_number),
            "v_type": vulnerability_type,
        }

    def _create_code_line(self, hunk: Hunk, hunk_line: int) -> int:
        result: int = hunk.target_start - 1
        for line in str(hunk).split("\n")[1:hunk_line]:
            if line.startswith("-"):
                continue
            result += 1
        return result
