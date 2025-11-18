#!/bin/bash

set -e

cd `dirname $0`

: "${LIBCXX_PATH:=/usr/lib/libc++.a}"
: "${CARGO_BUILD_FLAGS:=--release}"

if [ $CARGO_BUILD_FLAGS == "--release" ]; then
    export LIBFUZZER_CONCOLIC_PATH=target/release/libfuzzer_concolic.a
else 
    export LIBFUZZER_CONCOLIC_PATH=target/debug/libfuzzer_concolic.a
fi

cargo build $CARGO_BUILD_FLAGS

clang -shared -o libsymcc-rt.so \
-lpthread -lm -lrt -ldl \
-Wl,--whole-archive \
$LIBFUZZER_CONCOLIC_PATH $LIBCXX_PATH \
src/symcc_rt_main.c \
-Wl,--no-whole-archive
