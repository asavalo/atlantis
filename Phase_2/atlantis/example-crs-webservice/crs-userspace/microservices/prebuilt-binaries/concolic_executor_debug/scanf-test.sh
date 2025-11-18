#!/bin/sh
ROOT=`realpath $(dirname $0)`
clang -o scanf-test -L$ROOT -lsymcc-rt -Wl,-rpath=$ROOT scanf-test.c
$ROOT/scanf-test
