#!/bin/sh

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <binary> <input file>"
  exit 1
fi

binpath=$(realpath "$1")
input=$(realpath "$2")

# if [ ! -f $1 ]; then
#     binpath=$SCRIPT_DIR/$1
# else
#     binpath=$1
# fi

# if [ ! -f $2 ]; then
#     input=$SCRIPT_DIR/$2
# else
#     input=$2
# fi

# binpath=$(realpath "$binpath")
# input=$(realpath "$input")

SCRIPT_DIR=$(dirname "$(realpath "$0")")

# export SYMQEMU_SCRIPT=/home/user/symqemu-go/scripts/extract_panic_checks 
export SYMQEMU_TARGET_BINARY=$binpath
export SYMCC_OUTPUT_DIR=$SCRIPT_DIR/results
export SYMCC_INPUT_FILE=$input
# export SYMCC_NO_SYMBOLIC_INPUT=1

echo "SYMQEMU_TARGET_BINARY=$SYMQEMU_TARGET_BINARY"
echo "SYMCC_OUTPUT_DIR=$SYMCC_OUTPUT_DIR"
echo "SYMCC_INPUT_FILE=$SYMCC_INPUT_FILE"

echo "/home/user/symqemu-go/build/qemu-x86_64 $binpath $input"
/home/user/symqemu-go/build/qemu-x86_64 $binpath $input
# /home/user/work/symqemu/build/qemu-x86_64 $binpath $input
