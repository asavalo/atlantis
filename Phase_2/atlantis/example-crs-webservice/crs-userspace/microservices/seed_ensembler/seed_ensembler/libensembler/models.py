from dataclasses import dataclass
from pathlib import Path
import sys

if sys.version_info >= (3, 11):
    from typing import TYPE_CHECKING
    if TYPE_CHECKING:
        from typing import Self


@dataclass
class Configuration:
    """Represents app-wide configuration data from CLI arguments"""
    # Directory that libDeepGen will write its generated seeds into
    seeds_input_dir: Path

    # Directory that libDeepGen will look for feedback jsons in
    feedback_output_dir: Path

    # Directory to use for temporary files (ideally in ramfs/tmpfs)
    temp_dir: Path

    # Number of worker processes managing libfuzzer instances
    worker_pool_size: int

    # Number of recently seen seeds that the ensembler will remember, to
    # quickly filter out duplicates (None = unlimited)
    duplicate_seeds_cache_size: int | None

    # Whether to use inotify filesystem events to detect files created,
    # etc.
    use_inotify: bool

    # The runner Docker image name
    runner_docker_image: str | None

    # Manually set the group ID used to listen on Kafka topics (default:
    # "ensembler_{NODE_IDX}", using the NODE_IDX environment variable,
    # which defaults to "0")
    kafka_group_id: str | None

    # Whether verbose mode is enabled
    verbose: bool


@dataclass
class Harness:
    """Represents info about a particular harness"""
    # The name of the CP this harness is for
    cp_name: str

    # The unique identifier used to refer to the harness across the
    # whole CRS (probably the vanilla libfuzzer filename)
    name: str

    # The path to the vanilla libfuzzer build of this harness, within
    # the "out" directory artifact created by its build process
    path_in_out_dir: Path

    # The number of seconds a seed would need to execute to be
    # considered a scorable timeout.
    scorable_timeout_duration: int | None

    def to_dict(self) -> dict:
        return {
            'cp_name': self.cp_name,
            'name': self.name,
            'path_in_out_dir': str(self.path_in_out_dir),
            'scorable_timeout_duration': self.scorable_timeout_duration,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Self':
        return cls(
            data['cp_name'],
            data['name'],
            Path(data['path_in_out_dir']),
            data['scorable_timeout_duration'],
        )
