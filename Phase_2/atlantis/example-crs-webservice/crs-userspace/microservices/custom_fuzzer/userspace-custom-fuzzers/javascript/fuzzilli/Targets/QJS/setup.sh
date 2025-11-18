#!/bin/bash

SRC_DIR=$1

TARGET_DIR=/root/fuzzilli/Targets/QJS
cd $TARGET_DIR
# get codebase
cp -r $SRC_DIR ./qjs

cd ./qjs
patch -p1 < $TARGET_DIR/Patches/Fuzzilli-instrumentation-for-QJS.patch

echo "[+] Done preparing codebase"