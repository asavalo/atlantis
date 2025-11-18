import json
import re
from typing import TypedDict

import gdb  # type: ignore


def _is_asan_frame(frame: gdb.Frame | None) -> bool:
    if frame is None:
        return False

    symtab = frame.find_sal().symtab
    if not symtab:
        return False

    return bool(
        re.match(
            r"/src/llvm-project/compiler-rt/lib/asan/.+",
            symtab.filename,
        )
    )


def _find_non_asan_frame() -> gdb.Frame:
    frame = gdb.newest_frame()
    while frame and _is_asan_frame(frame):
        frame = frame.older()
    if not frame:
        raise gdb.GdbError("Failed to find a non-ASAN frame")
    return frame


class VariableInfo(TypedDict):
    """
    This class represents the information of a variable to be stored.
    It's same as the RuntimeInfo class in crete/framework/insighter/services/stacktrace/__init__.py
    """

    value: str | None
    type: str | None


class ASANDebug(gdb.Command):
    """Automatically analyze ASAN crash by running PoV, moving up non-ASAN frames and inspecting variables."""

    def __init__(self):
        super(ASANDebug, self).__init__("asan_debug", gdb.COMMAND_USER)

    def invoke(self, argument: str, from_tty: bool):
        try:
            depth, src_path, store_path = argument.strip().split()
            depth = int(depth)
        except ValueError:
            print("Usage: asan_debug <depth> <src_path> <store_path>")
            return

        gdb.execute(f"directory {src_path}")

        # https://github.com/google/sanitizers/wiki/AddressSanitizerAndDebugger
        bp = gdb.Breakpoint("__asan::ReportGenericError")
        if not bp.is_valid():
            print(" [-] ERROR: Failed to set breakpoint")
            return
        gdb.execute("run")
        if bp.hit_count == 0:
            print(" [-] ERROR: Breakpoint not hit")

        var_info: list[dict[str, VariableInfo]] = [{} for _ in range(depth)]
        frame = _find_non_asan_frame()

        for index in range(depth):
            gdb.execute(f"frame {frame.level()}")  # type: ignore

            # Get the call line source code
            sal = frame.find_sal()  # type: ignore
            if sal.symtab:
                filename = sal.symtab.filename
                lineno = sal.line
                output = gdb.execute(
                    f"list {filename}:{lineno},{lineno}", to_string=True
                )
                print(" [+] Source line: ", output)

                # Simple but effective
                variables = set(re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", output))
                print(" [+] Variables:", variables)

                for var in variables:
                    info = VariableInfo(value=None, type=None)
                    try:
                        info["value"] = gdb.execute(f"p {var}", to_string=True)
                    except gdb.error:
                        pass

                    try:
                        info["type"] = gdb.execute(f"ptype {var}", to_string=True)
                    except gdb.error:
                        pass

                    if info["value"] and info["type"]:
                        var_info[index][var] = info

            frame = frame.older()  # type: ignore
            if not frame:
                break

        print(" [+] ASAN Debugging Completed.")

        with open(store_path, "w") as f:
            json.dump(var_info, f, indent=2)
        print(f" [+] Stored runtime values to {store_path}")


ASANDebug()
