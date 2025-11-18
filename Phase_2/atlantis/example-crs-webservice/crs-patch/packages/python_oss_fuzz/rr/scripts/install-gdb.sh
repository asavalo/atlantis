#!/bin/bash
# This script is used by "packages/python_oss_fuzz/rr/scripts/Dockerfile"
set -e

apt update
apt install -y libmpfr-dev
wget https://sourceware.org/pub/gdb/releases/gdb-16.2.tar.gz
tar -xvf gdb-16.2.tar.gz
pushd gdb-16.2
ln -s /usr/bin/python3 python
./configure --with-python=$PWD
make -j$(nproc)
make install
popd

# clean up build directory to reduce image size
rm -rf gdb-16.2
