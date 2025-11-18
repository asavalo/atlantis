# Predicate offset to for benzene.
# Deprecated

import argparse
import subprocess
import time


def get_code_from_offset(cmd: str, offset):
    gdb_cmd = "\n\nb * 0x555555554000 + %s\nr\n" % hex(offset)
    p = subprocess.Popen(
        ["gdb", "--args"] + cmd.split(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    output, _ = p.communicate(input=gdb_cmd)
    p.wait()

    try:
        function_name = output.split("Breakpoint 1")[2].split("in ")[1].split()[0]
    except:
        function_name = output.split("Breakpoint 1")[2].split(" at ")[0]
    file_name = output.split("Breakpoint 1")[2].split(" at ")[1].split(":")[0]
    line_number = (
        output.split("Breakpoint 1")[2].split(" at ")[1].split(":")[1].split()[0]
    )
    code = (
        output.split("Breakpoint 1")[2]
        .split(" at ")[1]
        .split(":")[1]
        .split(line_number)[2]
        .split("\n")[0]
    )

    return function_name, file_name, line_number, code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get code from offset using gdb.")
    parser.add_argument("cmd", type=str, help="Command to run the program")
    parser.add_argument("offsets", type=str, help="Comma-separated list of offsets")
    args = parser.parse_args()

    cmd = args.cmd
    offsets = [int(offset, 16) for offset in args.offsets.split(",")]

    for offset in offsets:
        try:
            a, b, c, d = get_code_from_offset(cmd, offset)
        except Exception as e:
            print(f"Error processing offset {hex(offset)}: {e}")
            continue
        print("[*] offset: %s" % hex(offset))
        print(" - function_name: %s" % a)
        print(" - code line: %s:%s" % (b, c))
        print(" - code: %s" % d)
        time.sleep(1)
