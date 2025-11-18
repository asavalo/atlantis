#!/bin/bash
set -e
cd `dirname $0`

HARNESS=$(realpath ./binaries/libpng_read_fuzzer)
LLVM_SYMBOLIZER=$(realpath ./binaries/libpng_read_fuzzer-llvm-symbolizer)
LIBFUZZER_SYMBOL_TABLE_PATH=$(realpath ./libfuzzer-symbol-table.txt)
PRETTY_TRACE_FILE=./trace.json
QEMU=$(realpath ../build/qemu-x86_64)
INPUT_FILE=$(realpath ./input.txt)

cat /dev/urandom | head -c 100 > $INPUT_FILE

python3 ../scripts/extract-libfuzzer-symbols.py \
    $HARNESS > $LIBFUZZER_SYMBOL_TABLE_PATH

cargo run --bin concolic_utils run-symqemu \
    --harness $HARNESS \
    --qemu $QEMU \
    --input $INPUT_FILE \
    --timeout-ms 10000 \
    --workdir ./test \
    --llvm-symbolizer $LLVM_SYMBOLIZER \
    --dont-solve \
    --output out.json
