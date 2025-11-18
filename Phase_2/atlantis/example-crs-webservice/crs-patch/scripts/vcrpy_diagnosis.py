#! /usr/bin/env python3
import argparse
import difflib
import re
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("log_file", type=Path)
    return parser.parse_args()


def remove_timestamps(lines: list[str]) -> list[str]:
    return [
        re.sub(r"^.*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z ", "", line)
        for line in lines
    ]


def main():
    args = parse_args()
    lines = open(args.log_file).readlines()
    m = re.match(r"^.*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z", lines[0])
    if m:
        lines = remove_timestamps(lines)

    for i in range(1, len(lines)):
        if lines[i - 1].startswith("body - assertion failure"):
            inspect_assertion_failure(lines[i])


def inspect_assertion_failure(line: str):
    try:
        before, after = line.split("} != {")
    except ValueError:
        return

    # Security issue: eval is used to evaluate the string as a Python expression.
    # This can be a security risk if the input is not trusted.
    before = eval(before + "}")
    after = eval("{" + after)

    if len(before["messages"]) != len(after["messages"]):
        # print("[*] Length of messages is different")
        # print()
        return

    for i in range(len(before["messages"])):
        if before["messages"][i]["content"] != after["messages"][i]["content"]:
            print(f"[*] Message {i} is different")
            print(f"\tBefore: {before['messages'][i]['content']}")
            print("-" * 100)
            print(f"\tAfter: {after['messages'][i]['content']}")
            print("-" * 100)

            diff = difflib.ndiff(
                before["messages"][i]["content"].splitlines(),
                after["messages"][i]["content"].splitlines(),
            )
            print(f"\tDiff: {'\n'.join(diff)}")
            print("=" * 100)
            break
    else:
        # If the messages are the same, we need to inspect other parts
        del before["messages"]
        del after["messages"]
        print("[*] Metadata is different")
        print(f"\tBefore: {before}")
        print(f"\tAfter: {after}")
        print()


if __name__ == "__main__":
    main()
