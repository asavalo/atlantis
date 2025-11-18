#!/bin/bash
SYMCC_DIR=$(dirname $(realpath $0))/../..
cd $(dirname $(realpath $0))

set -e

export SYMCC_PASS_PATH=$SYMCC_DIR/build/libsymcc.so
export LIBSYMCC_RT_PATH=$SYMCC_DIR/../concolic_executor/libsymcc-rt.so
export ATLANTIS_CC_PATH=$SYMCC_DIR/../atlantis_cc/cc_wrapper
export ATLANTIS_CXX_PATH=$SYMCC_DIR/../atlantis_cc/cxx_wrapper
export ATLANTIS_CC_INSTRUMENTATION_MODE=symcc
export SYMCC_TRACE_FILE=trace.bin
export LIB_FUZZING_ENGINE=$SYMCC_DIR/../symcc-fuzzing-engine/build/libSymCCFuzzingEngine.a
export SYMCC_FUNCTION_CALL_HOOK=$(dirname $0)/hook.json

python3 write-hook.py

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

SRC="test-syscall.cpp"
EXECUTABLE="test-syscall"
clang++ -S -emit-llvm $CFLAGS -o $SRC-i.ll $SRC 
$ATLANTIS_CXX_PATH -S -emit-llvm $CFLAGS -o $SRC-o.ll $SRC 
$ATLANTIS_CXX_PATH $CFLAGS -o $EXECUTABLE $LIB_FUZZING_ENGINE $SRC 
cat /dev/urandom | head -c 1000 > sample.txt

./test-syscall sample.txt
