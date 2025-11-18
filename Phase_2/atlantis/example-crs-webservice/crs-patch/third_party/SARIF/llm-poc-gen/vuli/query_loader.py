import yaml
import logging
from pathlib import Path
from vuli.common.singleton import Singleton

class QueryLoader(metaclass=Singleton):
    _language = None

    def __init__(self, language=None):
        self._load_queries(language)
        self._language = language
        self._logger = logging.getLogger("QueryLoader")

    def _load_queries(self, language):
        query_file = Path("queries") / f"{language}.yaml"
        with open(query_file, "r", encoding="utf-8") as f:
            self.queries = yaml.safe_load(f)

    def get(self, key, **kwargs):
        val = self.queries.get(key)
        if val is None:
            self._logger.warning(f"Query '{key}' not found in {self._language}.yaml.")
            return ""
        return val.format(**kwargs) if kwargs else val