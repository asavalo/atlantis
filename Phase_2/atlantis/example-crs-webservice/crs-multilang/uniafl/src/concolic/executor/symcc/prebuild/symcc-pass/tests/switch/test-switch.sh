#!/bin/sh
set -e
cd $(dirname $0)
clang -S -o test-switch.ll \
      -emit-llvm \
      -Xclang -fdebug-pass-manager \
      -fpass-plugin=$(dirname $0)/../../build/libsymcc.so \
      -O3 \
      test-switch.c
