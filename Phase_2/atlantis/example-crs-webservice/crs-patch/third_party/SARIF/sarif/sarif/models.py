import csv
from pathlib import Path
from typing import TypeAlias

import yaml
from loguru import logger
from pydantic import BaseModel, Field

from sarif.tools.codeql.queries import get_abs_path
from sarif.types import LanguageT, OssFuzzLangT


# Configuration models
class ToolOptions(BaseModel):
    mode: str | None = None


class Tool(BaseModel):
    name: str
    options: ToolOptions | None = None


class LanguageReachabilityConfig(BaseModel):
    enabled: bool
    policy: str
    tool_list: list[Tool]


class ReachabilityConfig(BaseModel):
    c: LanguageReachabilityConfig
    java: LanguageReachabilityConfig


class SarifConfig(BaseModel):
    name: str
    reachability: ReachabilityConfig


class Harness(BaseModel):
    name: str
    path: Path
    class_paths: list[Path] = []  # for java


# CP model
class CP(BaseModel):
    name: str
    language: LanguageT
    oss_fuzz_lang: OssFuzzLangT | None = None
    harnesses: list[Harness] = []
    config_path: Path | None = None

    def model_post_init(self, __context):
        if self.config_path:
            self.get_harness_from_yaml(self.config_path)

        if self.language == "c":
            self.oss_fuzz_lang = "c"
        elif self.language == "cpp":
            self.language = "c"
            self.oss_fuzz_lang = "cpp"
        elif self.language == "java":
            self.oss_fuzz_lang = "jvm"

    def get_harness_from_yaml(self, yaml_path: Path):
        with open(yaml_path, "r") as f:
            yaml_data = yaml.safe_load(f)

        self.harnesses = [
            Harness(name=harness["name"], path=Path(harness["path"]))
            for harness in yaml_data["harness_files"]
        ]

    def update_harness_path(self, project_root: Path):
        for harness in self.harnesses:
            original_path = harness.path.as_posix()
            if "$PROJECT/" in original_path:
                harness.path = project_root / original_path.split("$PROJECT/")[1]

    def update_harness_path_from_codeql(self, codeql_db_path: Path):
        rel_paths = []

        for harness in self.harnesses:
            rel_path = (
                harness.path.as_posix().replace("$PROJECT", "").replace("$REPO", "")
            )
            rel_paths.append(rel_path)

        query = (
            get_abs_path("c")
            if self.language == "c" or self.language == "cpp"
            else get_abs_path("java")
        )
        query_res = query.run(
            database=codeql_db_path,
            params={"relative_paths": rel_paths},
        )
        results = query_res.parse()

        for result in results:
            for harness in self.harnesses:
                if result["base_name"] == harness.path.as_posix().split("/")[-1]:
                    harness.path = Path(result["abs_path"])
                    logger.info(
                        f"Updated harness path for {harness.name}: {harness.path}"
                    )


# Code models
class File(BaseModel):
    name: str
    path: Path


class Function(BaseModel):
    func_name: str
    file_name: str | None  # absolute path
    class_name: str | None = None
    func_sig: str | None = None
    method_desc: str | None = None
    start_line: int | None = None
    end_line: int | None = None

    def __hash__(self):
        # if self.func_sig is not None:
        #     hash_value = self.func_sig + "@" + self.file_name
        if self.class_name is not None:
            hash_value = self.class_name + "." + self.func_name
        else:
            hash_value = self.func_name + "@" + self.file_name
        return hash(hash_value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Function):
            return False

        if self.class_name is not None and other.class_name is not None:
            class_name_eq = self.class_name == other.class_name
        else:
            class_name_eq = True

        if self.func_sig is not None and other.func_sig is not None:
            func_sig_eq = self.func_sig == other.func_sig
        else:
            func_sig_eq = True

        file_name_eq = self.file_name.endswith(
            other.file_name
        ) or other.file_name.endswith(self.file_name)
        func_name_eq = self.func_name == other.func_name

        return file_name_eq and func_name_eq and class_name_eq and func_sig_eq


class FunctionCoverage(BaseModel):
    class_name: str
    file_name: str
    func_name: str
    desc: str


class FunctionTrace(BaseModel):
    trace: list[Function]


class CodeLocation(BaseModel):
    file: File
    function: Function | None = None
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None

    def validate(self):
        if self.function is None and self.start_line is None:
            raise ValueError("Function and start_line cannot be both None")


class ReachableFunction(Function):
    reached_by_fuzzers: list[str]


class FuzzerCoverage(BaseModel):
    cp: CP
    func_coverages: list[FunctionCoverage]

    @property
    def csv_path(self) -> Path:
        from sarif.context import SarifEnv

        return SarifEnv().out_dir / "function_coverage.csv"

    def to_csv(self) -> Path:
        with open(self.csv_path, "w") as f:
            writer = csv.writer(f)
            writer.writerow(["file_name", "func_name"])

            for func in self.func_coverages:
                writer.writerow([func.file_name, func.func_name])

        return self.csv_path


# Sarif threadFlows location
class ThreadFlowLocation(BaseModel):
    loc_file_full_name: str = Field(
        ..., description="The name of the file that the thread flow step occurs."
    )
    loc_file_short_name: str = Field(
        ..., description="The short name of the file that the thread flow step occurs."
    )
    loc_line: int = Field(
        ..., description="The line number that the thread flow step occurs."
    )
    message: str = Field(
        ..., description="A message that the describes the thread flow step."
    )


# Sarif threadFlow
class ThreadFlow(BaseModel):
    thread_flow_locations: list[ThreadFlowLocation] = Field(
        default_factory=list, description="A list of thread flows locations"
    )


# Sarif codeFlow
class CodeFlow(BaseModel):
    thread_flows: list[ThreadFlow] = Field(
        default_factory=list, description="A list of thread flows."
    )


# Sarif relatedLocation
class RelatedLocation(BaseModel):
    loc_file_full_name: str = Field(
        ..., description="The name of the file of the related location."
    )
    loc_file_short_name: str = Field(
        ..., description="The short name of the file of the related location."
    )
    loc_line: int = Field(..., description="The line number of the related location.")
    message: str = Field(
        ..., description="A message that the describes the related location."
    )


# Sarif information model
class SarifInfo(BaseModel):
    def __hash__(self):
        hash_value = (
            self.ruleId
            + self.code_locations[0].file.name
            + str(self.code_locations[0].start_line)
        )
        return hash(hash_value)

    ruleId: str = Field(
        ...,
        description="The stable, unique identifier of the rule, if any, to which this result is relevant.",
    )
    message: str = Field(
        ...,
        description="A message that describes the result. The first sentence of the message only will be displayed when visible space is limited.",
    )
    code_locations: list[CodeLocation] = Field(
        ...,
        description="The code locations of the result.",
    )

    related_locations: list[RelatedLocation] = Field(
        default_factory=list,
        description="List of related locations prividing additional context to the result.",
    )
    code_flows: list[CodeFlow] = Field(
        default_factory=list,
        description="List of code flows shows how the result came to be.",
    )


# CallPath model
class CallPath(BaseModel):
    path: list[Function]


class FunctionCall(BaseModel):
    caller: Function
    callee: Function

    def __hash__(self):
        return hash(self.caller) + hash(self.callee)


# Call Trace models
# C
class FunctionInfo_C(BaseModel):
    file: str
    line: int
    function_name: str

    def __hash__(self):
        return hash(self.file + self.function_name)


Callee_C: TypeAlias = FunctionInfo_C
Caller_C: TypeAlias = FunctionInfo_C


class CallState_C(BaseModel):
    file: str
    line: int
    callee: Callee_C


class Relation_C(BaseModel):
    caller: Caller_C
    callees: list[CallState_C]


Relations_C: TypeAlias = list[Relation_C]


# Java
class MethodInfo_Java(BaseModel):
    file: str
    prototype: str
    class_name: str
    method_name: str

    def __hash__(self):
        return hash(self.file + self.class_name + self.method_name)


Caller_Java: TypeAlias = MethodInfo_Java
Callee_Java: TypeAlias = MethodInfo_Java


class CallState_Java(BaseModel):
    file: str
    line: int
    callee: Callee_Java


class Relation_Java(BaseModel):
    caller: Caller_Java
    callees: list[CallState_Java]


Relations_Java: TypeAlias = list[Relation_Java]
