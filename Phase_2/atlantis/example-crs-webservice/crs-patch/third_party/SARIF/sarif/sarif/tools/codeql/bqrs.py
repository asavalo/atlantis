import csv
from typing import List

from sarif.tools.codeql.common import run, temporary_file


class BQRS(object):
    def __init__(self, path):
        self.path = path

    def run_command(self, command: str, options: List = [], post: List = []):
        return run(["bqrs", command] + options + [self.path])

    def parse(self) -> list[dict]:
        path = temporary_file(suffix=".csv")
        self.decode(format="csv", output=path)
        with open(path, "r") as f:
            csv_data = list(csv.reader(f, delimiter=","))

            keys = csv_data[0]
            values = csv_data[1:]

            return [dict(zip(keys, value)) for value in values]

    def info(self):
        self.run_command("info", ["-v"])

    def decode(self, format=None, output=None):
        options = []
        if format:
            options += [f"--format={format:s}"]
        if output:
            options += ["-o", output]
        self.run_command("decode", options)

    def diff(self, other):
        if type(other) == BQRS:
            other = other.path

        self.run_command("diff", post=[other])
