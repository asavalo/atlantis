from typing import Any

import yaml

# Use the libYAML versions if possible
try:
    from yaml import CDumper as Dumper
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Dumper, Loader

from tests.common.utils import make_portable, revert_portable


class PortableYamlSerializer:
    def deserialize(self, cassette_string: str) -> Any:
        return revert_portable(yaml.load(cassette_string, Loader=Loader))

    def serialize(self, cassette_dict: Any):
        return yaml.dump(make_portable(cassette_dict), Dumper=Dumper)
