#!/bin/bash

set -e

python3 -m venv ./meson-venv
export VENV=$(realpath ./meson-venv)
source $VENV/bin/activate
pip3 install setuptools
pip3 install meson
meson _build
ninja -C _build
ninja -C _build install
