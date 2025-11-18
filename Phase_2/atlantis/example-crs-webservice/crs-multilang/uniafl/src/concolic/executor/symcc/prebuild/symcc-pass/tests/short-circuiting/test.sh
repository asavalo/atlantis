#!/bin/sh
CURDIR=$(dirname "$0")
SYMCC_DIR=$CURDIR/../../
opt-18 \
	--load-pass-plugin=$SYMCC_DIR/build/libsymcc.so \
	--passes="function(scalarizer),module(SymbolizePass)" \
	-verify-each -S \
	-o test.o.ll test.i.ll
if [ $? -ne 0 ]; then
	echo "opt failed"
	exit 1
fi
