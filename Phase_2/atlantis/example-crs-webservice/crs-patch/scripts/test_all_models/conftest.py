import sys
from pathlib import Path

tests_path = str(Path(__file__).parent.parent.parent)
sys.path.insert(0, tests_path)

from tests.conftest import *  # noqa: E402, F403

sys.path.remove(tests_path)
