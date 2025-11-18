from __future__ import annotations

from cwe import Database
from markdown import markdown
from pydantic import BaseModel
from unidiff import PatchSet


class Patch(BaseModel):
    diff: str
    description: str | None = None
    cwe_id: str | None = None
    cve_id: str | None = None

    def as_document(self):
        if self.description is not None:
            description = f"## Description\n\n{markdown(self.description).strip()}\n\n"
        elif self.cwe_id is not None:
            cwe_database = Database()
            cwe = cwe_database.get(int(self.cwe_id.split("-")[1]))
            description = f"## Description\n\n{cwe.description}\n\n"
        else:
            description = ""

        source = f"## Source\n\n```\n{''.join(_source_from_diff(self.diff))}\n```\n\n"

        return f"""# Vulnerability Report\n\n\n{description}{source}""".strip()


def _source_from_diff(diff: str):
    for patched_file in PatchSet.from_string(diff):
        for hunk in patched_file:
            for line in hunk:
                if line.is_added:
                    continue
                else:
                    yield line.value
