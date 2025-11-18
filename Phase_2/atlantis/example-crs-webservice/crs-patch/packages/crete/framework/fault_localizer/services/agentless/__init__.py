import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, get_args

from litellm.types.utils import Choices, Message, ModelResponse
from python_llm.api.actors import LlmApiManager

from crete.atoms.detection import Detection
from crete.framework.fault_localizer.contexts import FaultLocalizationContext
from crete.framework.fault_localizer.functions import get_git_tracked_files
from crete.framework.fault_localizer.models import (
    FaultLocalizationResult,
    FaultLocation,
)
from crete.framework.fault_localizer.protocols import FaultLocalizerProtocol
from crete.framework.insighter.services.crash_log import CrashLogInsighter
from crete.framework.insighter.services.folded_code import FoldedCodeInsighter
from crete.framework.insighter.services.repository_structure import (
    RepositoryStructureInsighter,
)
from crete.framework.insighter.services.segmented_file import SegmentedFileInsighter
from crete.framework.language_parser.functions import get_declaration_by_line_range
from crete.framework.language_parser.models import Kind, LanguageNode

_RelatedElementType = Literal["variable", "function", "class"]


@dataclass
class _RelatedElement:
    type: _RelatedElementType
    value: str
    file: Path


class AgentlessFaultLocalizer(FaultLocalizerProtocol):
    _PROMPT_FOR_SUSPICIOUS_FILES = """Please look through the following Crash log and Repository structure and provide a list of files that one would need to edit to fix the problem.

### Crash log
{crash_log}

### Repository Structure
{repository_structure}

### Guidelines
Please only provide the full path and return at most 5 files.
The returned files should be separated by new lines ordered by most to least important and wrapped with ```
For example:
```
file1.py
file2.py
```
"""

    _PROMPT_FOR_RELATED_ELEMENTS = """Please look through the following Crash log and the Skeleton of Relevant Files.
Identify all locations that need inspection or editing to fix the problem, including directly related areas as well as any potentially related global variables, functions, and classes.
For each location you provide, either give the name of the class, the name of a method in a class, the name of a function, or the name of a global variable.

### Crash log
{crash_log}

### Skeleton of Relevant Files
{file_contents}

### Guidelines
Please provide the complete set of locations as either a class name, a function name, or a variable name.
Note that if you include a class, you do not need to list its specific methods.
You can include either the entire class or don't include the class name and instead include specific methods in the class.

### Examples:
```
full_path1/file1.py
function: my_function_1
class: MyClass1
function: MyClass2.my_method

full_path2/file2.py
variable: my_var
function: MyClass3.my_method

full_path3/file3.py
function: my_function_2
function: my_function_3
function: MyClass4.my_method_1
class: MyClass5
```

Return just the locations.
"""

    _PROMPT_FOR_EDIT_LOCATIONS = """Please review the following Crash log and relevant files, and provide a set of locations that need to be edited to fix the issue. The locations should be segments of lines that need to be modified.

### Crash log
{crash_log}

### Relevant Files
{file_contents}

### Guidelines
Please provide segments of lines that need to be edited for each file.

### Examples:
```
full_path1/file1.py
lines: 10-20
lines: 12-56

full_path2/file2.py
lines: 20-45
lines: 102-156
```

Return just the locations.
"""

    def __init__(
        self, llm_api_manager: LlmApiManager, context_window: int = 10
    ) -> None:
        self._llm_api_manager = llm_api_manager
        self._context_window = context_window

    def localize(
        self,
        context: FaultLocalizationContext,
        detection: Detection,
    ) -> FaultLocalizationResult:
        suspicious_files = self._localize_to_suspicious_files(context, detection)
        context["logger"].debug(
            f"- Step 1 - Localize to suspicious files: {suspicious_files}"
        )

        related_elements_by_path = self._localize_to_related_elements_by_path(
            context, detection, suspicious_files
        )

        context["logger"].debug(
            f"- Step 2 - Localize to related elements: {related_elements_by_path}"
        )

        edit_locations = self._localize_to_edit_locations(
            context, detection, suspicious_files, related_elements_by_path
        )

        context["logger"].debug(
            f"- Step 3 - Localize to edit locations: {edit_locations}"
        )

        return FaultLocalizationResult(locations=edit_locations)

    def _localize_to_suspicious_files(
        self, context: FaultLocalizationContext, detection: Detection
    ) -> list[Path]:
        with (
            self._llm_api_manager.litellm_completion() as completion  # pyright: ignore[reportUnknownVariableType]
        ):
            crash_log = CrashLogInsighter().create(context, detection)
            assert crash_log is not None, "Crash log is required"

            repository_structure = RepositoryStructureInsighter().create(
                context, detection
            )
            response = completion(
                messages=[
                    {
                        "role": "user",
                        "content": self._PROMPT_FOR_SUSPICIOUS_FILES.format(
                            crash_log=crash_log,
                            repository_structure=repository_structure,
                        ),
                    },
                ],
            )

        assert isinstance(response, ModelResponse), "Unreachable code"
        assert isinstance(response.choices[0], Choices), "Failed to get choices."
        assert isinstance(response.choices[0].message, Message), (
            "Failed to get message."
        )

        response_message = response.choices[0].message.content
        assert response_message is not None, "Failed to get message content."

        match _extract_from_code_block(response_message):
            case None:
                return []
            case match:
                return _response_to_files(context, match)

    def _make_insight_for_file_contents(
        self,
        context: FaultLocalizationContext,
        detection: Detection,
        suspicious_files: list[Path],
    ) -> str:
        insights: list[str] = []
        for file in suspicious_files:
            insight = FoldedCodeInsighter(file).create(context, detection)
            if insight is not None:
                insights.append(insight)
        return "\n".join(insights)

    def _localize_to_related_elements_by_path(
        self,
        context: FaultLocalizationContext,
        detection: Detection,
        suspicious_files: list[Path],
    ) -> dict[Path, list[_RelatedElement]]:
        with (
            self._llm_api_manager.litellm_completion() as completion  # pyright: ignore[reportUnknownVariableType]
        ):
            file_contents = self._make_insight_for_file_contents(
                context, detection, suspicious_files
            )
            crash_log = CrashLogInsighter().create(context, detection)
            repository_structure = RepositoryStructureInsighter().create(
                context, detection
            )

            response = completion(
                messages=[
                    {
                        "role": "user",
                        "content": self._PROMPT_FOR_RELATED_ELEMENTS.format(
                            crash_log=crash_log,
                            file_contents=file_contents,
                            repository_structure=repository_structure,
                        ),
                    },
                ],
            )

        assert isinstance(response, ModelResponse), "Unreachable code"
        assert isinstance(response.choices[0], Choices), "Failed to get choices."
        assert isinstance(response.choices[0].message, Message), (
            "Failed to get message."
        )

        response_message = response.choices[0].message.content
        assert response_message is not None, "Failed to get message content."

        match _extract_from_code_block(response_message):
            case None:
                return {}
            case match:
                return _response_to_related_elements_by_path(
                    context, match, suspicious_files
                )

    def _localize_to_edit_locations(
        self,
        context: FaultLocalizationContext,
        detection: Detection,
        suspicious_files: list[Path],
        related_elements: dict[Path, list[_RelatedElement]],
    ) -> list[FaultLocation]:
        with (
            self._llm_api_manager.litellm_completion() as completion  # pyright: ignore[reportUnknownVariableType]
        ):
            crash_log = CrashLogInsighter().create(context, detection)
            file_contents = self._make_insight_for_segmented_files(
                context, detection, related_elements
            )

            response = completion(
                messages=[
                    {
                        "role": "user",
                        "content": self._PROMPT_FOR_EDIT_LOCATIONS.format(
                            crash_log=crash_log,
                            file_contents=file_contents,
                        ),
                    },
                ],
            )

        assert isinstance(response, ModelResponse), "Unreachable code"
        assert isinstance(response.choices[0], Choices), "Failed to get choices."
        assert isinstance(response.choices[0].message, Message), (
            "Failed to get message."
        )

        response_message = response.choices[0].message.content
        assert response_message is not None, "Failed to get message content."

        match _extract_from_code_block(response_message):
            case None:
                return []
            case match:
                return _response_to_edit_locations(
                    context, match, suspicious_files, related_elements
                )

    def _make_insight_for_segmented_files(
        self,
        context: FaultLocalizationContext,
        detection: Detection,
        related_elements: dict[Path, list[_RelatedElement]],
    ) -> str:
        insights: list[str] = []
        for file, elements in related_elements.items():
            insight = SegmentedFileInsighter(
                file, self._get_segments_from_elements(context, file, elements)
            ).create(context, detection)

            if insight is not None:
                insights.append(insight)
        return "\n".join(insights)

    def _get_segments_from_elements(
        self,
        context: FaultLocalizationContext,
        file: Path,
        elements: list[_RelatedElement],
    ) -> list[tuple[int, int]]:
        lines = file.read_text(errors="replace").splitlines()
        segments: list[tuple[int, int]] = []

        for element in elements:
            for name, declaration in context[
                "language_parser"
            ].get_declarations_in_file(context, file):
                if declaration.kind not in [Kind.FUNCTION, Kind.CLASS]:
                    continue

                # If name includes function arguments, remove them
                if "(" in name:
                    name = name.split("(")[0]

                # e.g., name = "func1" and element.value = "func1"
                #       name = "Class1.method1" and element.value = "method1"
                if name.endswith(element.value):
                    segments.append(
                        (
                            max(0, declaration.start_line - self._context_window),
                            min(
                                len(lines), declaration.end_line + self._context_window
                            ),
                        )
                    )

        return segments


def _response_to_files(context: FaultLocalizationContext, response: str) -> list[Path]:
    """
    An example response:
    file1.py
    file2.py
    """

    context["logger"].debug(f"Response to files:\n{response}")
    target_files: list[Path] = []
    tracked_files = get_git_tracked_files(context["pool"].source_directory)
    tracked_files = [context["pool"].source_directory / file for file in tracked_files]

    for line in response.splitlines():
        if not line.strip():
            continue

        for file in tracked_files:
            if str(file).endswith(line.strip()):
                target_files.append(file)

    return target_files


def _response_to_related_elements_by_path(
    context: FaultLocalizationContext, response: str, suspicious_files: list[Path]
) -> dict[Path, list[_RelatedElement]]:
    """
    An example response:

    '''
    full_path1/file1.py
    function: my_function_1
    class: MyClass1
    function: MyClass2.my_method

    full_path2/file2.py
    variable: my_var
    function: MyClass3.my_method

    full_path3/file3.py
    function: my_function_2
    function: my_function_3
    function: MyClass4.my_method_1
    class: MyClass5
    '''
    """

    context["logger"].debug(f"Response to related elements:\n{response}")
    related_elements_by_path: dict[Path, list[_RelatedElement]] = {}

    for file_level_response in response.split("\n\n"):
        related_elements: list[_RelatedElement] = []
        lines = file_level_response.strip().splitlines()
        if len(lines) == 0:
            continue

        file = _find_file_by_suffix(suspicious_files, lines[0].strip())
        if file is None:
            continue

        for line in lines[1:]:
            match re.search(r"(\w+): (.+)", line.strip()):
                case None:
                    continue
                case match:
                    type, value = match.groups()
                    if type not in get_args(_RelatedElementType):
                        continue

                    related_elements.append(_RelatedElement(type, value, file))  # type: ignore

        if len(related_elements) > 0:
            related_elements_by_path[file] = related_elements

    return related_elements_by_path


def _response_to_edit_locations(
    context: FaultLocalizationContext,
    response: str,
    suspicious_files: list[Path],
    related_elements_by_path: dict[Path, list[_RelatedElement]],
) -> list[FaultLocation]:
    """
    An example response:

    '''
    full_path1/file1.py
    lines: 10-20
    lines: 12-56

    full_path2/file2.py
    lines: 20-45
    lines: 102-156
    '''
    """

    context["logger"].debug(f"Response to edit locations:\n{response}")
    edit_locations: list[FaultLocation] = []
    for file_level_response in response.split("\n\n"):
        related_elements: list[_RelatedElement] = []
        lines = file_level_response.strip().splitlines()
        if len(lines) == 0:
            continue

        file = _find_file_by_suffix(suspicious_files, lines[0].strip())
        if file is None:
            context["logger"].warning(f"File not found: {lines[0].strip()}")
            continue

        for line in lines[1:]:
            start = end = None
            # e.g., lines: 10-20
            match re.search(r"lines: (\d+)-(\d+)", line.strip()):
                case None:
                    pass
                case match:
                    start, end = int(match.group(1)), int(match.group(2))

            if start is None or end is None:
                # e.g., lines: 10
                match re.search(r"lines: (\d+)", line.strip()):
                    case None:
                        continue
                    case match:
                        start = int(match.group(1))
                        end = start + 1

            assert isinstance(start, int) and isinstance(end, int), "Unreachable code"

            declaration = get_declaration_by_line_range(
                context["language_parser"],
                context,
                file,
                (start, end),
            )

            edit_locations.append(
                FaultLocation(
                    file=file,
                    function_name=_function_or_class_name(declaration),
                    line_range=(start, end),
                )
            )

        if len(related_elements) > 0:
            related_elements_by_path[file] = related_elements

    return edit_locations


def _extract_from_code_block(response: str) -> str | None:
    match re.search(r"```[^\n]*\n(.+)```", response, re.MULTILINE | re.DOTALL):
        case None:
            return None
        case match:
            return match.group(1).strip()


def _find_file_by_suffix(files: list[Path], suffix: str) -> Path | None:
    for file in files:
        # 1. Remove /src from the suffix
        suffix = suffix.replace("/src", "")
        # 2. Normalize paths to handle a case like "/src/test/../samples/mock_vp.c"
        if os.path.normpath(file).endswith(os.path.normpath(suffix)):
            return file
    return None


def _function_or_class_name(declaration: tuple[str, LanguageNode] | None) -> str | None:
    if declaration is None:
        return None
    name, node = declaration
    if node.kind not in [Kind.FUNCTION, Kind.CLASS]:
        return None
    return name
