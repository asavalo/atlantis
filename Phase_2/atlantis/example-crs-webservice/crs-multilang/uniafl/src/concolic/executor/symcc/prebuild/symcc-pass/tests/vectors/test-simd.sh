#!/bin/bash
SYMCC_DIR=$(dirname $(realpath $0))/../..
cd $(dirname $(realpath $0))

set -e

export SYMCC_PASS_PATH=$SYMCC_DIR/build/libsymcc.so
export LIBSYMCC_RT_PATH=$SYMCC_DIR/../concolic_executor/libsymcc-rt.so
export ATLANTIS_CC_PATH=$SYMCC_DIR/../atlantis_cc/cc_wrapper
export ATLANTIS_CC_INSTRUMENTATION_MODE=symcc
export SYMCC_TRACE_FILE=trace.json
export SYMCC_ENABLE_FULL_TRACE=1
export SYMCC_TRACE_JSON=1
export LIB_FUZZING_ENGINE=$SYMCC_DIR/../symcc-fuzzing-engine/build/libSymCCFuzzingEngine.a

if [ ! -f $ATLANTIS_CC_PATH ]; then
    echo "Atlantis CC not found at $ATLANTIS_CC_PATH"
    exit 1
fi

if [ ! -f $SYMCC_PASS_PATH ]; then
    echo "SymCC pass not found at $SYMCC_PASS_PATH"
    exit 1
fi

if [ ! -f $LIBSYMCC_RT_PATH ]; then
    echo "SymCC runtime not found at $LIBSYMCC_RT_PATH"
    exit 1
fi

if [ ! -f $LIB_FUZZING_ENGINE ]; then
    echo "SymCC fuzzing engine not found at $LIB_FUZZING_ENGINE"
    exit 1
fi

CFLAGS="-mavx2"
clang -S -emit-llvm $CFLAGS -o test-simd1-i.ll test-simd1.c
$ATLANTIS_CC_PATH -S -emit-llvm $CFLAGS -o test-simd1-o.ll test-simd1.c
$ATLANTIS_CC_PATH $CFLAGS -o test-simd1 $LIB_FUZZING_ENGINE test-simd1.c
cat /dev/urandom | head -c 1000 > sample.txt

./test-simd1 sample.txt
python3 decode.py $SYMCC_TRACE_FILE
