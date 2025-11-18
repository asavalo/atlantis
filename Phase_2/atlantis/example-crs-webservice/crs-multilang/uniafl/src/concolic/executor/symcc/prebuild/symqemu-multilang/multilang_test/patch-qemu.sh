#!/bin/sh
QEMU_PATH=$(dirname $0)/../build/qemu-x86_64
SYMCC_PATH=$(realpath $(dirname $0)/../../concolic_executor/libsymcc-rt.so)

if [ -f $SYMCC_PATH ]; then
    echo "libsymcc-rt.so found!"
else
    echo "libsymcc-rt.so not found!"
    exit 1
fi

if [ -f $QEMU_PATH ]; then
    echo "PatchELFing QEMU binary..."
    patchelf \
        --replace-needed libSymCCRtShared.so libsymcc-rt.so \
        --set-rpath $(dirname $SYMCC_PATH) \
        $QEMU_PATH
    echo "QEMU binary patched!"
    ldd $QEMU_PATH
else
    echo "QEMU binary not found!"
fi
