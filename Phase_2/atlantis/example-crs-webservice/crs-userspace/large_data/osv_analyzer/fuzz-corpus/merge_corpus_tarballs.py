#!/usr/bin/env python3

import os
import sys
import shutil
import tempfile
import tarfile
import hashlib
from pathlib import Path
import argparse
import zstandard as zstd
import logging


def extract_tar_zst(tar_zst_path, extract_dir):
    logging.debug(f'Extracting {tar_zst_path} to {extract_dir}')
    with open(tar_zst_path, 'rb') as compressed:
        dctx = zstd.ZstdDecompressor()
        with dctx.stream_reader(compressed) as reader:
            with tarfile.open(fileobj=reader, mode='r:') as tar:
                tar.extractall(path=extract_dir)
    logging.debug(f'Extraction complete: {tar_zst_path}')


def create_tar_zst(src_dir, tar_zst_path):
    logging.debug(f'Creating tar.zst from {src_dir} to {tar_zst_path}')
    with tempfile.NamedTemporaryFile(delete=False) as tmp_tar:
        with tarfile.open(fileobj=tmp_tar, mode='w') as tar:
            tar.add(src_dir, arcname='.')
        tmp_tar_path = tmp_tar.name
    cctx = zstd.ZstdCompressor(level=19, threads=0)
    with open(tmp_tar_path, 'rb') as src, open(tar_zst_path, 'wb') as dst:
        cctx.copy_stream(src, dst)
    os.remove(tmp_tar_path)
    logging.debug(f'Created tar.zst: {tar_zst_path}')


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    checksum = h.hexdigest()
    logging.debug(f'Checksum for {path}: {checksum}')
    return checksum


def main():
    parser = argparse.ArgumentParser(description='Merge tarballs into ./fuzz_corpus, deduplicating by checksum.')
    parser.add_argument('src_dir', help='Directory containing tarballs to merge')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='[%(levelname)s] %(message)s'
    )

    src_dir = Path(args.src_dir)
    dst_dir = Path('./fuzz_corpus')
    dst_dir.mkdir(exist_ok=True)

    for src_tar in src_dir.glob('*.tar.zst'):
        name = src_tar.name
        dst_tar = dst_dir / name
        logging.info(f'Processing tarball: {name}')

        if dst_tar.exists():
            logging.info(f'Merging {name} (exists in destination)')
            with tempfile.TemporaryDirectory(prefix='merge_corpus_dst_') as tmp_dst, \
                 tempfile.TemporaryDirectory(prefix='merge_corpus_src_') as tmp_src, \
                 tempfile.TemporaryDirectory(prefix='merge_corpus_merge_') as tmp_merge:
                try:
                    extract_tar_zst(dst_tar, tmp_dst)
                    extract_tar_zst(src_tar, tmp_src)
                except Exception as e:
                    logging.error(f'Error extracting tarballs: {e}')
                    continue

                seen = set()
                # Copy files from existing corpus first
                for root, _, files in os.walk(tmp_dst):
                    for file in files:
                        src_path = Path(root) / file
                        rel_path = src_path.relative_to(tmp_dst)
                        checksum = file_sha256(src_path)
                        seen.add(checksum)
                        out_path = Path(tmp_merge) / rel_path
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src_path, out_path)
                        logging.debug(f'Copied existing file: {rel_path}')

                # Add new files from src if not already present
                for root, _, files in os.walk(tmp_src):
                    for file in files:
                        src_path = Path(root) / file
                        rel_path = src_path.relative_to(tmp_src)
                        checksum = file_sha256(src_path)
                        if checksum not in seen:
                            out_path = Path(tmp_merge) / rel_path
                            out_path.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(src_path, out_path)
                            seen.add(checksum)
                            logging.debug(f'Added new file from src: {rel_path}')
                        else:
                            logging.debug(f'Skipped duplicate file from src: {rel_path}')

                try:
                    create_tar_zst(tmp_merge, dst_tar)
                    logging.info(f'    - ✅ Merged: {dst_tar}')
                except Exception as e:
                    logging.error(f'Error creating merged tarball: {e}')
        else:
            logging.info(f'Copying new tarball {name} (not in destination)')
            try:
                shutil.copy2(src_tar, dst_tar)
                logging.info(f'    - ✅ Copied: {dst_tar}')
            except Exception as e:
                logging.error(f'Error copying tarball: {e}')

    logging.info('[✓] Merge complete.')

if __name__ == '__main__':
    main() 