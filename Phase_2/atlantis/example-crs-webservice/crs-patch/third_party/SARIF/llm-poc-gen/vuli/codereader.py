from pathlib import Path

from vuli.joern import Joern
from vuli.struct import CodePoint
from vuli.query_loader import QueryLoader


def create_code_table(path: list[CodePoint]) -> dict:
    methods: list[str] = [method for method in dict.fromkeys([x.method for x in path])]
    params = {
        "method_list": ",".join([f"\"{method}\"" for method in methods])
    }
    joern_query: str = QueryLoader().get("create_code_table", **params)
    joern_result: list[dict] = Joern().run_query(joern_query)
    code_table: dict = {}
    [
        code_table.setdefault(x["filename"], []).append((x["lineNumber"], x["lineNumberEnd"]))
        for x in joern_result
    ]
    code_table: dict = {
        key: sorted(value, key=lambda x: int(x[0])) for key, value in code_table.items()
    }
    return code_table


class BaseReader:
    def __init__(self, source_dir: Path):
        self.__source_dir = source_dir

    def read(self, path: Path, with_line: bool = False):
        lines = self.readlines(path, with_line)
        return "".join(lines)

    def read_by_table(self, table: dict) -> str:
        result: str = ""
        for file, info in table.items():
            lines: list[str] = self.readlines(Path(file), True)
            for i in reversed(range(0, len(lines))):
                keep: bool = False
                for start_idx, end_idx in info:
                    if (i + 1 <= end_idx) and (i + 1 >= start_idx):
                        keep = True
                        break
                if not keep:
                    del lines[i]
            if len(result) != 0:
                result += "\n"
            result += f"{file}:\n{"".join(lines)}"
        return result

    def readlines(self, path: Path, with_line: bool = False):
        with (self.__source_dir / path).open() as f:
            lines: list[str] = f.readlines()

        if with_line:
            line_number_width: int = len(str(len(lines)))
            lines: list[str] = [
                f"{str(index + 1).rjust(line_number_width)}   {line}"
                for index, line in enumerate(lines)
            ]
        return lines
