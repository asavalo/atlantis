#!/bin/bash -e

if [ "$FUZZING_LANGUAGE" = "c" ] || [ "$FUZZING_LANGUAGE" = "c++" ]; then
    if [ -f /work/compile_commands.json ]; then
        echo "compile_commands.json already built"
        exit 0
    fi
    bear --cdb /work/compile_commands.json compile
elif [ "$FUZZING_LANGUAGE" = "java" ]; then
    echo "This is Java LSP image, nothing to prepare or build"
    exit 0
fi
