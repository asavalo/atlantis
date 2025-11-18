from pathlib import Path

## Crete directories
ROOT_DIRECTORY = Path(__file__).parent.parent.parent.parent
DEFAULT_CACHE_DIRECTORY = ROOT_DIRECTORY / ".cache"
PACKAGES_DIRECTORY = ROOT_DIRECTORY / "packages"
THIRD_PARTY_DIRECTORY = ROOT_DIRECTORY / "third_party"
