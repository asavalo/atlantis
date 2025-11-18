from pydantic import BaseModel, Field
import typing
import re
import os
from pathlib import Path
import glob


class StackFrame(BaseModel):
    funcname: str = Field(
        default="Unknown",
        title="Function Name",
        description="The name of the function in the call stack",
    )
    filepath: str = Field(
        default="Unknown",
        title="File Path",
        description="The path of the file where the function is located",
    )
    lineno: int = Field(
        default=-1,
        title="Line Number",
        description="The line number in the file where the function is called",
    )
    colno: int = Field(
        default=-1,
        title="Column Number",
        description="The column number in the file where the function is called (if applicable)",
    )


class CrashReport(BaseModel):
    rule_id: str = Field(
        default="Unknown",
        title="Rule ID",
        description="The rule id that matched this crash report",
    )
    stacktrace: typing.List[StackFrame] = Field(
        default=[],
        title="Stacktrace",
        description="The list of call records in the stack trace leading to this crash report",
    )

    @classmethod
    def from_bytes(cls, data: bytes, lang: typing.Literal["c", "jvm"]) -> "CrashReport":
        # Remove ANSI escape sequences
        data = re.sub(rb"\x1b\[1m\x1b\[[0-9]+m", b"", data)
        data = re.sub(rb"\x1b\[0m\x00", b"", data)
        match lang:
            case "c":
                pattern = re.compile(
                    rb"^\s*#\d+ 0x[0-9a-fA-F]+ in(\ *)(?P<funcname>.*) (?P<filepath>[^ :]+):(?P<lineno>\d+):(?P<colno>\d+)",
                    re.M,
                )
                matches = pattern.finditer(data)
                stacktrace = list()
                for match in matches:
                    stacktrace.append(StackFrame(**match.groupdict()))

                pattern = re.compile(
                    rb"ERROR: [a-zA-Z]+Sanitizer:\ *([^:]*?(?=:| \bon\b|$))", re.M
                )
                rule_id = pattern.search(data)
                if rule_id:
                    rule_id = rule_id.group(1).decode("utf-8")
                else:
                    rule_id = "Unknown"

                return CrashReport(
                    rule_id=rule_id,
                    stacktrace=stacktrace,
                )
            case "jvm":
                pattern = re.compile(
                    rb"^\s*at (?P<package>.*)\((?P<filename>.*):(?P<lineno>\d+)\)\s*$",
                    re.MULTILINE,
                )
                matches = pattern.finditer(data)
                stacktrace = list()
                for match in matches:
                    fields = match.groupdict()
                    package = fields["package"]
                    filename = fields["filename"]
                    lineno = int(fields["lineno"])

                    funcname = package.split(b".")[-1].strip()
                    filepath = (
                        package[: package.rfind(b".")].replace(b".", b"/") + b".java"
                    )

                    stacktrace.append(
                        StackFrame(
                            funcname=funcname,
                            filepath=filepath,
                            lineno=lineno,
                        )
                    )

                # TODO: This cannot handle the following case
                # oss-fuzz/projects/aixcc/jvm/aerospike/.aixcc/crash_logs/AerospikeOne/cpv_0.log
                # == Java Exception: java.lang.ArrayStoreException: com.code_intelligence.jazzer.runtime.HardToCatchError
                pattern = re.compile(
                    rb"com.code_intelligence.jazzer.api.[a-zA-Z]+:\ *([^:]*?(?=:|$))",
                    re.M,
                )
                rule_id = pattern.search(data)
                if rule_id:
                    rule_id = rule_id.group(1).decode("utf-8").strip()
                else:
                    rule_id = "Unknown"

                return CrashReport(
                    rule_id=rule_id,
                    stacktrace=stacktrace,
                )
            case _:
                raise ValueError(f"Unsupported language: {lang}")


if __name__ == "__main__":
    if os.getenv("OSS_FUZZ_DIR") is None:
        print("OSS_FUZZ_DIR is not set")
        exit(-1)

    jvm_crashlogs = glob.glob(
        f"{os.getenv('OSS_FUZZ_DIR')}/projects/aixcc/jvm/*/.aixcc/crash_logs/*/*"
    )

    for jvm_crashlog in jvm_crashlogs:
        with open(jvm_crashlog, "rb") as f:
            crashlog = CrashReport.from_bytes(f.read(), "jvm")
            print(jvm_crashlog)
            print(crashlog.model_dump_json(indent=2))

    c_crashlogs = glob.glob(
        f"{os.getenv('OSS_FUZZ_DIR')}/projects/aixcc/c/*/.aixcc/crash_logs/*/*"
    ) + glob.glob(
        f"{os.getenv('OSS_FUZZ_DIR')}/projects/aixcc/cpp/*/.aixcc/crash_logs/*/*"
    )

    for c_crashlog in c_crashlogs:
        with open(c_crashlog, "rb") as f:
            crashlog = CrashReport.from_bytes(f.read(), "c")
            print(c_crashlog)
            print(crashlog.model_dump_json(indent=2))
