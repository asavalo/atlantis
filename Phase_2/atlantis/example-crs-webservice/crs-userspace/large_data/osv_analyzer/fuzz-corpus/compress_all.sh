#!/bin/bash
set -euo pipefail

ROOT_DIR="./fuzz_corpus"

for dir in "$ROOT_DIR"/*; do
  [ -d "$dir" ] || continue
  name=$(basename "$dir")
  out="$ROOT_DIR/$name.tar.zst"

  echo "[+] Compressing $name..."
  tar -cf - -C "$dir" . | zstd -19 -T0 -o "$out"
  rm -rf "$dir"
  echo "    - ✅ Done: $out"
done

echo "[✓] All compressed."
