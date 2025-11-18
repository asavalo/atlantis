import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from python_aixcc_challenge.language.types import Language
from python_ctags import CTAGS_EXECUTABLE_FILE

from crete.commons.interaction.functions import run_command
from crete.framework.language_parser.services.ctags.models import CtagEntry, TagKind


class CtagsParser:
    """
    Parser for ctags output in JSON format.

    This class handles running ctags on a project directory and parsing the output
    to provide structured access to tags information.
    """

    def __init__(self, proj_path: Path, tags_path: Path, lang: Language):
        """
        Initialize the CtagsParser.

        Args:
            proj_path: Path to the project directory
            tags_path: Path where tags file will be stored
            lang: Programming language to parse

        Raises:
            FileNotFoundError: If project path doesn't exist
        """
        self.proj_path = proj_path.absolute()
        self.tags_path = tags_path.absolute()
        self.lang: Language = lang
        self._tags: Optional[List[CtagEntry]] = None

        if not self.proj_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {self.proj_path}")

    @property
    def tags(self) -> List[CtagEntry]:
        """
        Lazily load the tags file.

        Returns:
            List[CtagEntry]: List of parsed tag entries
        """
        if self._tags is None:
            if self.tags_path.exists():
                self.tags_path.unlink()
            self._run_ctags()
            self._tags = self._parse_tags_with_json()
        return self._tags

    def _run_ctags(self) -> None:
        """
        Run ctags on the project directory and save the output.

        Raises:
            NotImplementedError: If language is not supported
            RuntimeError: If ctags command fails
        """
        ctags_command = self._get_ctags_command()

        try:
            run_command((ctags_command, self.proj_path))
            self._convert_to_complete_json(self.tags_path)
        except Exception as e:
            raise RuntimeError(f"Failed to run ctags: {e}") from e

    def _get_ctags_command(self) -> str:
        if self.lang in ["c", "cpp", "c++"]:
            return f"{CTAGS_EXECUTABLE_FILE} --output-format=json -R -f {self.tags_path} --languages=C,C++ --fields=+n {self.proj_path}"
        elif self.lang == "jvm":
            return f"{CTAGS_EXECUTABLE_FILE} --output-format=json -R -f {self.tags_path} --languages=Java --fields=+n {self.proj_path}"
        else:
            raise NotImplementedError(f"Language {self.lang} is not supported")

    def _parse_tags_with_json(self) -> List[CtagEntry]:
        try:
            with open(self.tags_path, "r") as f:
                tags_array = json.load(f)
        except (IOError, json.JSONDecodeError):
            raise

        entries: List[CtagEntry] = []
        for entry_dict in tags_array:
            try:
                tag_entry = _parse_tag_entry_from_dict(entry_dict, self.proj_path)
                if tag_entry is not None:
                    entries.append(tag_entry)
            except Exception:
                continue

        return entries

    def get_entry_at_line(
        self,
        abs_src_path: Path,
        line_num: int,
        toplevel: bool = True,
        entry_kind: TagKind | None = None,
    ) -> CtagEntry | None:
        assert abs_src_path.is_absolute()

        target_entry = None
        for cur_tag_entry in self.tags:
            if cur_tag_entry.abs_src_path != abs_src_path:
                continue

            if entry_kind is not None and cur_tag_entry.kind != entry_kind:
                continue

            if cur_tag_entry.line > line_num:
                continue

            if toplevel and cur_tag_entry.scope is not None:
                continue

            if target_entry is None or target_entry.line < cur_tag_entry.line:
                target_entry = cur_tag_entry

        return target_entry

    def get_entry_before_line(
        self,
        abs_src_path: Path,
        line_num: int,
        toplevel: bool = True,
        entry_kind: TagKind | None = None,
    ) -> CtagEntry | None:
        assert abs_src_path.is_absolute()

        target_entry = None
        for cur_tag_entry in self.tags:
            if cur_tag_entry.abs_src_path != abs_src_path:
                continue

            if entry_kind is not None and cur_tag_entry.kind != entry_kind:
                continue

            if cur_tag_entry.line > line_num:
                continue

            if toplevel and cur_tag_entry.scope is not None:
                continue

            if target_entry is None or target_entry.line < cur_tag_entry.line:
                target_entry = cur_tag_entry

        return target_entry

    def get_entry_after_line(
        self,
        abs_src_path: Path,
        line_num: int,
        toplevel: bool = True,
        entry_kind: TagKind | None = None,
    ) -> CtagEntry | None:
        assert abs_src_path.is_absolute()

        target_entry = None
        for cur_tag_entry in self.tags:
            if cur_tag_entry.abs_src_path != abs_src_path:
                continue

            if entry_kind is not None and cur_tag_entry.kind != entry_kind:
                continue

            if cur_tag_entry.line < line_num:
                continue

            if toplevel and cur_tag_entry.scope is not None:
                continue

            if target_entry is None or target_entry.line > cur_tag_entry.line:
                target_entry = cur_tag_entry

        return target_entry

    def get_tag_entries_by_name(self, name: str) -> List[CtagEntry]:
        return [tag_entry for tag_entry in self.tags if tag_entry.name == name]

    def get_all_functions(self) -> List[CtagEntry]:
        return self._collect_entries_with_tag_kinds([TagKind.FUNCTION])

    def get_all_variables(self) -> List[CtagEntry]:
        return self._collect_entries_with_tag_kinds([TagKind.VARIABLE])

    def get_all_macros(self) -> List[CtagEntry]:
        return self._collect_entries_with_tag_kinds([TagKind.MACRO])

    def get_all_structs_or_unions(self) -> List[CtagEntry]:
        return self._collect_entries_with_tag_kinds([TagKind.STRUCT, TagKind.UNION])

    def get_all_typedefs(self) -> List[CtagEntry]:
        return self._collect_entries_with_tag_kinds([TagKind.TYPEDEF])

    def get_all_members(self) -> List[CtagEntry]:
        return self._collect_entries_with_tag_kinds([TagKind.MEMBER])

    def get_all_enums(self) -> List[CtagEntry]:
        return self._collect_entries_with_tag_kinds([TagKind.ENUM])

    def get_all_enumerators(self) -> List[CtagEntry]:
        return self._collect_entries_with_tag_kinds([TagKind.ENUMERATOR])

    def get_all_methods(self) -> List[CtagEntry]:
        return self._collect_entries_with_tag_kinds([TagKind.METHOD])

    def get_all_enum_constants(self) -> List[CtagEntry]:
        return self._collect_entries_with_tag_kinds([TagKind.ENUMCONSTANT])

    def get_all_classes(self) -> List[CtagEntry]:
        return self._collect_entries_with_tag_kinds([TagKind.CLASS])

    def get_all_interfaces(self) -> List[CtagEntry]:
        return self._collect_entries_with_tag_kinds([TagKind.INTERFACE])

    def get_all_fields(self) -> List[CtagEntry]:
        return self._collect_entries_with_tag_kinds([TagKind.FIELD])

    def get_all_annotations(self) -> List[CtagEntry]:
        return self._collect_entries_with_tag_kinds([TagKind.ANNOTATION])

    def _collect_entries_with_tag_kinds(self, kinds: List[TagKind]) -> List[CtagEntry]:
        return [tag_entry for tag_entry in self.tags if tag_entry.kind in kinds]

    def _convert_to_complete_json(self, tags_path: Path) -> None:
        try:
            tag_lines = tags_path.read_text(encoding="utf-8").splitlines()
            tags_txt = f"[{',\n'.join(tag_lines)}]"
            tags_path.write_text(tags_txt, encoding="utf-8")
        except Exception:
            raise


def _extract_raw_string_from_pattern_field(pattern_field: str) -> str:
    pattern_regex_type1 = r"/\^(.*)(?:\$|[ ])/"
    pattern_regex_type2 = r"/\^(.*)/"

    match = re.match(pattern_regex_type1, pattern_field)
    if match is None:
        match = re.match(pattern_regex_type2, pattern_field)

    if match is None:
        raise ValueError(
            f'Failed to extract raw string from pattern field: "{pattern_field}"'
        )

    return _remove_additional_backslashes_in_pattern(match.group(1))


def _remove_additional_backslashes_in_pattern(pattern: str) -> str:
    pattern = pattern.replace("\\/", "/")
    pattern = pattern.replace("\\\\", "\\")
    return pattern.rstrip()


def _parse_tag_entry_from_dict(
    entry_dict: Dict[str, Any], base_path: Path
) -> Optional[CtagEntry]:
    # Skip pseudo-tags
    if entry_dict.get("_type") == "ptag":
        return None

    # Skip unnamed tags
    name_str = entry_dict.get("name")
    if name_str is not None and "__anon" in name_str:
        return None

    scope_str = entry_dict.get("scope")
    if scope_str is not None and "__anon" in scope_str:
        return None

    try:
        abs_src_path = Path(entry_dict["path"])

        return CtagEntry(
            abs_src_path=abs_src_path,
            rel_src_path=abs_src_path.relative_to(base_path),
            line=int(entry_dict["line"]),
            name=str(entry_dict["name"]),
            pattern=_extract_raw_string_from_pattern_field(entry_dict["pattern"]),
            kind=TagKind(entry_dict["kind"]),
            scope=entry_dict.get("scope"),
        )
    except (KeyError, ValueError):
        return None
