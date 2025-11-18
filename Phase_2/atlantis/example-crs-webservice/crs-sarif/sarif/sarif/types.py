from typing import Literal, TypeVar

from pydantic import BaseModel

PromptOutputT = TypeVar("PromptRet", bound=BaseModel)

LanguageT = Literal["c", "cpp", "java"]
OssFuzzLangT = Literal["c", "cpp", "jvm"]
