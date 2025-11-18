#!/bin/sh
echo 0 | SYMQEMU_SCRIPT=/home/user/symqemu-go/scripts/extract_panic_checks SYMQEMU_TARGET_BINARY=/home/user/symqemu-go/tests/symqemu/binaries/index/index ~/symqemu-go/build/qemu-x86_64 ./index
