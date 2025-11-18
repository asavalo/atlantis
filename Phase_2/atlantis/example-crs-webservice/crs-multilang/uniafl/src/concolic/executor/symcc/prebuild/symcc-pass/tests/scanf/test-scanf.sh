#!/bin/sh
clang -o test-scanf.ll \
      -emit-llvm -S \
      -fpass-plugin=$(dirname $0)/../build/libsymcc.so \
      test-scanf.c
clang -o test-scanf -L ../concolic_executor_debug/ -lsymcc-rt test-scanf.ll && \
	objdump -d test-scanf > test-scanf.S && \
	rm -f test-scanf
