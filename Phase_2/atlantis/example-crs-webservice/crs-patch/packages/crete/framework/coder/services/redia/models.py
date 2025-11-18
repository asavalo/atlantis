from pydantic import BaseModel, Field


class Replacement(BaseModel):
    search: str = Field(
        description=(
            "A code snippet (including any whitespace, comments, or docstrings) "
            "to find within the file. This should match exactly as it appears in "
            "the existing file contents."
        )
    )
    replace: str = Field(
        description=("The code snippet that will replace the matched 'search' code.")
    )


class PatchedFile(BaseModel):
    file_path: str = Field(
        description=("The absolute path to the target file that needs to be edited.")
    )
    replacements: list[Replacement] = Field(
        description=(
            "A list of 'search and replace' operations, each specifying what exact code "
            "to look for and what to replace it with in the given file."
        )
    )


class PatchSet(BaseModel):
    patches: list[PatchedFile] = Field(
        description=(
            "A collection of file-level patches that together define a set of "
            "specific code replacements across one or more files."
        )
    )
