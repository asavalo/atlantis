#!/bin/bash

set -e
cd $(dirname $0)

export CC=clang
export CXX=clang++

python3 -m venv ./symqemu-venv
export SYMQEMU_VENV=$(realpath ./symqemu-venv)
$SYMQEMU_VENV/bin/pip3 install meson tomli
cat <<EOF > ./configure_symqemu.sh
../configure                                                    \
      --audio-drv-list=                                         \
      --disable-sdl                                             \
      --disable-gtk                                             \
      --disable-vte                                             \
      --disable-opengl                                          \
      --disable-virglrenderer                                   \
      --target-list=x86_64-linux-user                           \
      --python=$SYMQEMU_VENV/bin/python3 \
      --ninja=$(which ninja) \
      --disable-werror \
      --extra-ldflags="-lc++ -ldl" \
      --extra-cxxflags="-std=c++17" \
      --symcc-rt-backend=qsym
EOF

chmod u+x ./configure_symqemu.sh
mkdir build
cd build
../configure_symqemu.sh
ninja -t compdb > compile_commands.json
ninja
