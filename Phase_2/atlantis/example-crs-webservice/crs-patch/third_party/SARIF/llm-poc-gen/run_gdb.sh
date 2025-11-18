#!/bin/bash
set -e

if [ $# -lt 3 ]; then
  echo "Usage: $0 <binary> <filename> <breakpoint1> [breakpoint2 ...] --dir <src_dir1> [src_dir2 ...]"
  exit 1
fi

BINARY=$1
INPUT=/app/llm-poc-gen/temp_dir/$2
OUTPUT=/app/llm-poc-gen/shared/logs/$2
shift 2

BREAKPOINTS=()
SRC_DIRS=()
SRC_MODE=0

for arg in "$@"; do
  if [[ "$arg" == "--dir" ]]; then
    SRC_MODE=1
    continue
  fi

  if [[ $SRC_MODE -eq 1 ]]; then
    SRC_DIRS+=("$arg")
  else
    BREAKPOINTS+=("$arg")
  fi
done

GDB_CMD="/app/llm-poc-gen/shared/gdb_cmd.txt"

# === GDB command script ===
echo "set pagination off" > "$GDB_CMD"
echo "set filename-display absolute" >> "$GDB_CMD"

for dir in "${SRC_DIRS[@]}"; do
  echo "directory $dir" >> "$GDB_CMD"
done

for bp in "${BREAKPOINTS[@]}"; do
  echo "break $bp" >> "$GDB_CMD"
done

# echo "info breakpoints" >> "$GDB_CMD"
echo "run $INPUT" >> "$GDB_CMD"
echo "while 1" >> "$GDB_CMD"
echo "  continue" >> "$GDB_CMD"
# echo "  bt" >> "$GDB_CMD"
echo "end" >> "$GDB_CMD"
echo "quit" >> "$GDB_CMD"

# === Run GDB ===
gdb -q -batch -x "$GDB_CMD" --args "$BINARY" -runs=1 -timeout=10 "$INPUT" &> "$OUTPUT"

echo "GDB output written to $OUTPUT"