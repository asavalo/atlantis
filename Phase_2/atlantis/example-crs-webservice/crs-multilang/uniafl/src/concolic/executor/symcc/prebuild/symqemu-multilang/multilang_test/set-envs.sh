#!/bin/sh
export SYMQEMU_HOME=$(realpath $(dirname $0)/../)
export LIBFUZZER_SERVER=1
export SYMQEMU_SHM=/symqemu-shmem
export SYMQEMU_WORKER_IDX=1
export SYMCC_TRACE_FILE=./trace-1.json
export LIBFUZZER_SYMBOL_TBL=$(realpath $(dirname $0)/libfuzzer-symbol-table.txt)
