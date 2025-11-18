#!/bin/bash
set -e
cd `dirname $0`

HARNESS=$(realpath ./fuzzer)
LIBFUZZER_SYMBOL_TABLE_PATH=$(realpath ./libfuzzer-symbol-table.txt)
TRACE_FILE=$(realpath ./trace.json)
QEMU=$(realpath ../build/qemu-x86_64)

python3 ../scripts/extract-libfuzzer-symbols.py \
    $HARNESS > $LIBFUZZER_SYMBOL_TABLE_PATH

cd trigger
cargo run -- \
    --harness $HARNESS \
    --qemu $QEMU \
    --trace-file $TRACE_FILE \
    --libfuzzer-symbol-table-path $LIBFUZZER_SYMBOL_TABLE_PATH
