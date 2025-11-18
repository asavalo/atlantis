#!/bin/sh -e

PORT=${PORT:-7000}

if [ "$FUZZING_LANGUAGE" = "c" ] || [ "$FUZZING_LANGUAGE" = "c++" ]; then
    LANGUAGE_SERVER_CMD="clangd-18"

    # See prepare.sh - this is for persisting the compile_commands.json file
    cp /work/compile_commands.json . || true
elif [ "$FUZZING_LANGUAGE" = "jvm" ]; then
    LANGUAGE_SERVER_CMD="/opt/eclipse-jdt-ls/bin/jdtls -data /work"
fi

timeout 48h socat TCP-LISTEN:$PORT,reuseaddr,fork EXEC:"$LANGUAGE_SERVER_CMD"
