from typing import TypedDict

from joblib import Memory


class CachingContext(TypedDict):
    memory: Memory
    sanitizer_name: str
