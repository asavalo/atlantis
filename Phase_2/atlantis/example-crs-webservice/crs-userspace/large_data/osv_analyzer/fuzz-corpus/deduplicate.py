#!/usr/bin/env python3

from pathlib import Path
import hashlib
import shutil

def compute_sha256(file_path: Path, chunk_size: int = 8192) -> str:
    """Compute SHA256 hash of a file."""
    hasher = hashlib.sha256()
    with file_path.open('rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

def remove_duplicates(src_dir: Path, target_dir: Path):
    """Copy unique files from src_dir to target_dir, renamed by their SHA256 hash."""
    seen_hashes = set()
    target_dir.mkdir(parents=True, exist_ok=True)

    for file_path in src_dir.rglob('*'):
        if file_path.is_file():
            try:
                file_hash = compute_sha256(file_path)
                ext = file_path.suffix
                new_name = f"{file_hash[:16]}"
                new_path = target_dir / new_name

                if file_hash in seen_hashes or new_path.exists():
                    print(f"Skipping duplicate: {file_path}")
                    continue

                print(f"Copying: {file_path} → {new_path}")
                shutil.copy2(file_path, new_path)
                seen_hashes.add(file_hash)

            except Exception as e:
                print(f"Error processing {file_path}: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python script.py <src_dir> <target_dir>")
    else:
        src = Path(sys.argv[1])
        dst = Path(sys.argv[2])

        if not src.is_dir():
            print(f"{src} is not a directory.")
        else:
            remove_duplicates(src, dst)
