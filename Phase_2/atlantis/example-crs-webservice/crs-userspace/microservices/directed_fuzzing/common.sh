#!/bin/bash

set -e

# --- BULLSEYE_TASK_DIR must be set ---
# it is done in the Dockerfile; and defaults to /df_task
if [ -z "$BULLSEYE_TASK_DIR" ]; then
    echo "Error: BULLSEYE_TASK_DIR environment variable is not set"
    exit 1
fi

# --- Set default for BULLSEYE_FUZZ_OUT based on BULLSEYE_TASK_DIR ---
: "${BULLSEYE_FUZZ_OUT:=$BULLSEYE_TASK_DIR/bullseye-fuzz-out}"
mkdir -p "$BULLSEYE_FUZZ_OUT" || { echo "Error: Failed to create BULLSEYE_FUZZ_OUT directory '$BULLSEYE_FUZZ_OUT'"; exit 1; }

# now we go into the task dir
pushd "$BULLSEYE_TASK_DIR" || { echo "Failed to pushd to $BULLSEYE_TASK_DIR"; exit 1; }

# --- Check BULLSEYE_TARGET_LOC environment variable (required) ---
if [ -z "$BULLSEYE_TARGET_LOC" ]; then
    echo "Error: BULLSEYE_TARGET_LOC environment variable is not set"
    exit 1
fi

# --- Check BULLSEYE_BC_FILE environment variable (required) ---
if [ -z "$BULLSEYE_BC_FILE" ]; then
    echo "Error: BULLSEYE_BC_FILE environment variable is not set"
    exit 1
fi

# --- Validate BULLSEYE_BC_FILE ends with .bc (required) ---
if [[ ! "$BULLSEYE_BC_FILE" =~ \.bc$ ]]; then
    echo "Error: BULLSEYE_BC_FILE ('$BULLSEYE_BC_FILE') must end with .bc"
    exit 1
fi

# Check BULLSEYE_BC_FILE exists in the current directory (required)
if [ ! -f "$BULLSEYE_BC_FILE" ]; then
    echo "Error: File '$BULLSEYE_BC_FILE' not found in $BULLSEYE_TASK_DIR"
    exit 1
fi

# --- Check for userIndCall.txt (optional) ---
# This file is used if SVF's analysis failed to get the indirect calls; this
# could happen for many reason due to incompleteness of static analysis. This
# file can complement the analysis by providing the mapping from callsite to
# function names, i.e.:
# cjpeg.c:640,start_input_bmp
# cjpeg.c:664,get_rgb_row
if [ -f "userIndCall.txt" ]; then
    export BULLSEYE_USER_SPECIFIED_IND_CALL=$(paste -sd';' userIndCall.txt)
fi

# --- Check BULLSEYE_CONTEXT_MAX_DEPTH environment variable (optional) ---
# This controls the context-sensitive analysis of bullseye. More depth
# means more accurate landmark selection. However, this is very expensive;
# especially in complex programs. By default, the context depth is set to 2.
# You can tune it down to 1 for some projects with this env.
if [ -n "$BULLSEYE_CONTEXT_MAX_DEPTH" ]; then
    if [[ ! "$BULLSEYE_CONTEXT_MAX_DEPTH" =~ ^[1-3]$ ]]; then
        echo "Error: BULLSEYE_CONTEXT_MAX_DEPTH must be a number between 1 and 3 (got '$BULLSEYE_CONTEXT_MAX_DEPTH')"
        exit 1
    fi
fi

# --- Check LINKAGE_FLAGS environment variable (optional) ---
if [ -n "$BULLSEYE_LINKAGE_FLAGS" ]; then
    if [ ! -d "shared-libs" ]; then
        echo "Error: 'shared-libs/' directory is required for BULLSEYE_LINKAGE_FLAGS but not found."
        echo "BULLSEYE_LINKAGE_FLAGS: $BULLSEYE_LINKAGE_FLAGS"
        exit 1
    fi

    # Set extra linker flags to find libs in shared-libs/
    export BULLSEYE_EXTRA_LINK_FLAGS="-L$BULLSEYE_TASK_DIR/shared-libs"

    # Also prepare LD_LIBRARY_PATH for runtime
    export LD_LIBRARY_PATH="$BULLSEYE_TASK_DIR/shared-libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

# --- Select compiler based on BULLSEYE_BC_COMPILER (default to c) ---
: "${BULLSEYE_BC_COMPILER:=c}"  # Default to c if not set
if [ "$BULLSEYE_BC_COMPILER" = "c" ]; then
    COMPILER="/directed_fuzzing/Bullseye/afl-clang-fast"
elif [ "$BULLSEYE_BC_COMPILER" = "cpp" ]; then
    COMPILER="/directed_fuzzing/Bullseye/afl-clang-fast++"
else
    echo "Error: Unknown language '$BULLSEYE_BC_COMPILER'. Must be 'c' or 'cpp'."
    exit 1
fi

# --- Ensure seed_corpus directory and seed file (optional) ---
BULLSEYE_INPUT_CORPUS_DIR="seed_corpus"

if [ ! -d "$BULLSEYE_INPUT_CORPUS_DIR" ]; then
    echo "seed_corpus directory does not exist. Creating it..."
    mkdir "$BULLSEYE_INPUT_CORPUS_DIR" || { echo "Error: Failed to create seed_corpus directory"; exit 1; }
    echo "AAAA" > "$BULLSEYE_INPUT_CORPUS_DIR/seed.txt"
else
    # seed_corpus exists, check if it has any files
    if [ -z "$(find "$BULLSEYE_INPUT_CORPUS_DIR" -type f -print -quit)" ]; then
        echo "seed_corpus directory is empty. Adding seed file..."
        echo "AAAA" > "$BULLSEYE_INPUT_CORPUS_DIR/seed.txt"
    fi
fi

# --- Handle BULLSEYE_SANITIZER ---
if [ -n "$BULLSEYE_SANITIZER" ]; then
    case "$BULLSEYE_SANITIZER" in
        address)
            export AFL_USE_ASAN=1
            ;;
        memory)
            export AFL_USE_MSAN=1
            ;;
        undefined)
            export AFL_USE_UBSAN=1
            ;;
        *)
            echo "Error: Unknown BULLSEYE_SANITIZER '$BULLSEYE_SANITIZER'. Expected ASAN, MSAN, or UBSAN."
            exit 1
            ;;
    esac
fi

BULLSEYE_INPUT_CORPUS="$BULLSEYE_TASK_DIR/$BULLSEYE_INPUT_CORPUS_DIR"
BULLSEYE_BC_BASENAME="${BULLSEYE_BC_FILE%.bc}"
BULLSEYE_BUILD_DIR="$BULLSEYE_TASK_DIR/bullseye-${BULLSEYE_BC_BASENAME}-build"
BULLSEYE_FUZZ_BIN="$BULLSEYE_BUILD_DIR/fuzz-bullseye-${BULLSEYE_BC_BASENAME}"
BULLSEYE_LOOPS_SIMPLIFIED="${BULLSEYE_BC_BASENAME}-loop-simplified.bc"
