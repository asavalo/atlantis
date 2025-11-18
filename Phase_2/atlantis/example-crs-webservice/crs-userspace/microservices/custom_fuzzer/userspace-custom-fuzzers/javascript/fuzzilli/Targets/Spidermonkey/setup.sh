#!/bin/bash

SRC_DIR=$1

# get codebase
cp -r $SRC_DIR ./spidermonkey

# bootstrap
cd ./spidermonkey
./mach --no-interactive bootstrap --application-choice js

echo "[+] Done preparing codebase"