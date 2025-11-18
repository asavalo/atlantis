import os
import inspect
from loguru import logger

from sarif.sarif.matcher.agent.state import SarifMatchingState


class ByLinenoRetriever:
    def __init__(self, src_dir: str):
        self.src_dir = src_dir

    def __call__(self, retrieve_query: str) -> SarifMatchingState:
        if retrieve_query is None:
            return None

        query = retrieve_query.split(":")
        if len(query) != 3 or query[0] != "BY_LINENO":
            return None

        file_path = query[1]
        start, end = query[2].split("-")
        try:
            start = int(start)
        except:
            start = 1
        try:
            end = int(end)
        except:
            end = 0xFFFFFFFF

        lines = list()
        while True:
            try:
                with open(os.path.join(self.src_dir, file_path), "r") as f:
                    lines = f.readlines()
                break
            except FileNotFoundError:
                file_path = "/".join(file_path.split("/")[1:])
                if file_path == "":
                    break
            except:
                break

        source_code = "".join(lines[start - 1 : end])
        retrieved = inspect.cleandoc(
            f"""
// {file_path}:{start}-{end}
{inspect.cleandoc(source_code)}
"""
        )

        return retrieved


if __name__ == "__main__":
    retriever = ByLinenoRetriever("/home/kyuheon/example-libpng")
    print(retriever("BY_LINENO:pngrutil.c:1421-1447"))
