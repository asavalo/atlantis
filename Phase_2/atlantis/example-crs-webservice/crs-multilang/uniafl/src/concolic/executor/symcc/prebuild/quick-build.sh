#!/bin/sh
set -e
sudo rm -rf symqemu-multilang/build
docker run --rm -it -v $(pwd):/prebuild -w /prebuild/symqemu-multilang multilang-builder ./build.sh
sudo cp symqemu-multilang/build/qemu-x86_64 /symcc/qemu-x86_64
sudo patchelf --replace-needed libSymCCRtShared.so libsymcc-rt.so /symcc/qemu-x86_64
sudo patchelf --set-rpath /symcc /symcc/qemu-x86_64
