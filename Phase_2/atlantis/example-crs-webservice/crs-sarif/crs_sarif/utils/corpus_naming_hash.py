import subprocess
from tempfile import TemporaryDirectory
from pathlib import Path

from crs_sarif.utils.context import CRSEnv


def get_corpus_hash(corpus_data: bytes) -> str:
    hash_engine_path = CRSEnv().corpus_hash_engine_path
    if not hash_engine_path.exists():
        raise FileNotFoundError(f"Hash engine not found at {hash_engine_path}")

    with TemporaryDirectory() as temp_dir:
        temp_dir = Path(temp_dir)

        with open(temp_dir / "corpus.bin", "wb") as f:
            f.write(corpus_data)

        result = subprocess.run(
            [hash_engine_path, temp_dir / "corpus.bin"], capture_output=True, text=True
        )
        return result.stdout.strip()
