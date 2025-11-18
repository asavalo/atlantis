#!/usr/bin/env python3
import argparse
import json
import subprocess
from pathlib import Path

def parse_maps(pid, executable):
    base_addr = None
    end_addr = None
    maps_path = f"/proc/{pid}/maps"
    try:
        with open(maps_path, "r") as maps_file:
            for line in maps_file:
                if executable in line:
                    parts = line.split()
                    addr_range = parts[0]
                    base_str, end_str = addr_range.split('-')
                    base_addr = int(base_str, 16)
                    end_addr = int(end_str, 16)
                    break
    except FileNotFoundError:
        print(f"Error: Could not open {maps_path}")
    return base_addr, end_addr

def symbolize_offset(executable: Path, offset: int):
    cmd = ["llvm-symbolizer-18", f"--obj={executable}", hex(offset)]
    try:
        output = subprocess.check_output(cmd, stdin=subprocess.DEVNULL, universal_newlines=True)
        return output.strip()
    except subprocess.CalledProcessError as e:
        return f"Error symbolizing offset {hex(offset)}: {e}"

def main():
    parser = argparse.ArgumentParser(
        description="Symbolize addresses from a trace JSON file for a PIE executable."
    )
    parser.add_argument("-p", "--pid", required=True, help="PID of the QEMU process")
    parser.add_argument("-e", "--executable", required=True, help="Path to the executable")
    parser.add_argument("-i", "--input", required=True, help="Path to the trace JSON file")
    args = parser.parse_args()

    # Read the trace JSON file.
    try:
        with open(args.input, "r") as json_file:
            trace = json.load(json_file)
    except Exception as err:
        print(f"Error reading trace JSON file: {err}")
        return

    # Parse the maps file for the executable's mapping.
    base_addr, end_addr = parse_maps(args.pid, args.executable)
    if base_addr is None or end_addr is None:
        print("Error: Could not find mapping for the executable in /proc/<pid>/maps.")
        return

    print(f"Executable mapping for {args.executable}:")
    print(f"  Base address: {hex(base_addr)}")
    print(f"  End address:  {hex(end_addr)}\n")

    # Process each entry in the trace file.
    for entry in trace:
        if not (isinstance(entry, list) or isinstance(entry, tuple)) or len(entry) != 2:
            continue

        id_val, trace_obj = entry
        if "PathConstraint" in trace_obj:
            pc_obj = trace_obj["PathConstraint"]
            location = pc_obj.get("location")
            if location is None:
                continue

            if base_addr <= location < end_addr:
                offset = location - base_addr
                print(f"Entry ID {id_val}:")
                print(f"  Location: {hex(location)} is within mapping.")
                print(f"  Offset:   {hex(offset)}")
                symbol_output = symbolize_offset(args.executable, offset)
                print("  Symbolized info:")
                print(symbol_output, "\n")

if __name__ == "__main__":
    main()
