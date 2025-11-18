from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sys

if sys.version_info >= (3, 11):
    from typing import TYPE_CHECKING
    if TYPE_CHECKING:
        from typing import Self


@dataclass
class SeedsBatchFeedback:
    """
    Feedback sent from the ensembler to libDeepGen about a batch of
    seeds it was given
    """

    # Did this batch of seeds add any new coverage?
    new_coverage: bool

    # Should this script be cancelled due to causing too many crashes or
    # timeouts?
    should_cancel_script: bool

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=4)

    @classmethod
    def from_json(cls, data: str) -> 'Self':
        return cls(**json.loads(data))

    def save_to_file(self, path: Path) -> None:
        with path.open('w', encoding='utf-8') as f:
            json.dump(asdict(self), f, indent=4)

    @classmethod
    def from_file(cls, path: Path) -> 'Self':
        with path.open('r', encoding='utf-8') as f:
            return cls(**json.load(f))
