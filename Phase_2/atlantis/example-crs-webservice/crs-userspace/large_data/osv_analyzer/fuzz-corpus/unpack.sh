#!/bin/bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 archive.tar.zst output_dir"
  exit 1
fi

ARCHIVE="$1"
OUTDIR="$2"

mkdir -p "$OUTDIR"
unzstd -c "$ARCHIVE" | tar -xf - -C "$OUTDIR"

echo "[✓] Extracted $ARCHIVE to $OUTDIR"