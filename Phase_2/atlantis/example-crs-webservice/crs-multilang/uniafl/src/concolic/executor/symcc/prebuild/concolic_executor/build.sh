#!/bin/bash

set -e

cd `dirname $0`

: "${LIBCXX_PATH:=/usr/lib/libc++.a}"
: "${CARGO_BUILD_FLAGS:=--release}"
: "${PYTHON_INSTALL_PATH:=/symcc/python3.14}"

if [ $CARGO_BUILD_FLAGS == "--release" ]; then
    export LIBFUZZER_CONCOLIC_PATH=target/release/libconcolic_executor.a
else 
    export LIBFUZZER_CONCOLIC_PATH=target/debug/libconcolic_executor.a
fi

if [[ "$CARGO_BUILD_FLAGS" == *"--debug"* ]]; then 
    export CARGO_BUILD_FLAGS=${CARGO_BUILD_FLAGS/--debug/}
fi

VENV_DIR=$(realpath "./symcc-venv")

# Step 1: Create the virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment '$VENV_DIR' already exists."
fi

$VENV_DIR/bin/pip install --upgrade pip
$VENV_DIR/bin/pip install -r requirements.txt

source $VENV_DIR/bin/activate

cargo build $CARGO_BUILD_FLAGS

clang -shared -o libsymcc-rt.so \
-fPIC \
-lpthread -lm -lrt -ldl \
-Wl,--whole-archive \
$LIBFUZZER_CONCOLIC_PATH \
$LIBCXX_PATH \
-Wl,--no-whole-archive \
-L$PYTHON_INSTALL_PATH/lib -lpython3.14 -Wl,-rpath,$PYTHON_INSTALL_PATH/lib \
src/weak_symbols.c
