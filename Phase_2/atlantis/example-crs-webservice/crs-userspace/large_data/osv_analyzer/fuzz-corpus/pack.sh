#!/bin/bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 input_dir output.tar.zst"
  exit 1
fi

INPUT_DIR="$1"
OUTPUT_FILE="$2"

tar -cf - -C "$INPUT_DIR" . | zstd -19 -T0 -o "$OUTPUT_FILE"

echo "[✓] Packed $INPUT_DIR to $OUTPUT_FILE"