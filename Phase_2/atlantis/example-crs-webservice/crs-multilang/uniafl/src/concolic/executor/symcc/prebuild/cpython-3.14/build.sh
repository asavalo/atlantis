#!/bin/bash

set -e

: "${INSTALL_PREFIX:=/symcc/python3.14}"

DIR=$(dirname $0)
cd $DIR
cp ./multilang-setup.local Modules/Setup.local

./configure --prefix=$INSTALL_PREFIX \
	--enable-shared
make -j$(nproc)
make altinstall
cp $INSTALL_PREFIX/lib/libpython3.14.so .
