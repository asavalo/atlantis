import csv
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List

import polars as pl
from loguru import logger

from sarif.tools.codeql.common import run, temporary_file


class BQRS(object):
    def __init__(self, path):
        self.path = path

    def run_command(self, command: str, options: List = [], post: List = []):
        return run(["bqrs", command] + options + [self.path])

    def parse(self) -> list[dict]:
        logger.info(f"Parsing BQRS file {self.path}")
        start_time = time.time()

        path = temporary_file(suffix=".csv")
        self.decode(format="csv", output=path)

        try:
            df = pl.read_csv(path, infer_schema=False)
            return df.to_dicts()
        finally:
            Path(path).unlink(missing_ok=True)

            end_time = time.time()
            logger.info(
                f"Parsed BQRS file {self.path} in {end_time - start_time} seconds"
            )

    def parse_chunked(self, chunk_size: int = 10000) -> Iterator[list[dict]]:
        logger.info(f"Parsing BQRS file {self.path} in chunks")
        start_time = time.time()

        path = temporary_file(suffix=".csv")
        self.decode(format="csv", output=path)

        try:
            df = pl.scan_csv(path, infer_schema=False)
            total_rows = df.collect().height

            for offset in range(0, total_rows, chunk_size):
                chunk_df = df.slice(offset, chunk_size).collect()
                yield chunk_df.to_dicts()
        finally:
            Path(path).unlink(missing_ok=True)

        end_time = time.time()
        logger.info(f"Parsed BQRS file {self.path} in {end_time - start_time} seconds")

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
