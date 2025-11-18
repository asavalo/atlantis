#!/bin/bash

source /directed_fuzzing/common.sh

if [ -d "$BULLSEYE_BUILD_DIR" ]; then
    echo "Warning: BULLSEYE_BUILD_DIR '$BULLSEYE_BUILD_DIR' already exists. Removing it."
    rm -rf "$BULLSEYE_BUILD_DIR"
fi

mkdir -p "$BULLSEYE_BUILD_DIR"

pushd "$BULLSEYE_BUILD_DIR"
  # we copy the artifacts files to the build dir
  # because some programs have files needed there during fuzzing
  # i.e. file program use magic.mgc files
  shopt -s dotglob
  cp -r $BULLSEYE_ARTIFACTS_DIR/* .
  shopt -u dotglob

  export BULLSEYE_OUTPUT_DIR="$(pwd)"

  cp ../$BULLSEYE_BC_FILE ./$BULLSEYE_BC_FILE

  if [ -n "$BULLSEYE_SANITIZER" ]; then
    # if sanitizer is enabled; we need to manually add the sanitize_address
    # attribute to functions:
    # https://github.com/google/sanitizers/issues/1476
    opt-18 -load-pass-plugin=/directed_fuzzing/Bullseye/AddSan.so -passes=add-sanitize-address -o $BULLSEYE_BC_FILE < $BULLSEYE_BC_FILE
    if [ $? -ne 0 ]; then
      echo "Error: failed to apply the AddSan pass."
      exit 1
    fi
  fi

  opt-18 -passes=loop-simplify,mem2reg -o $BULLSEYE_LOOPS_SIMPLIFIED $BULLSEYE_BC_FILE
  if [ $? -ne 0 ] || [ ! -f "$BULLSEYE_LOOPS_SIMPLIFIED" ]; then
      echo "Error: opt-18 failed or output file '$BULLSEYE_LOOPS_SIMPLIFIED' not found"
      exit 1
  fi

  alias_analyses=("Andersen" "Steensgaard")
  for alias_analysis in "${alias_analyses[@]}"; do
    echo "Running Bullseye with $alias_analysis alias analysis..."
    export BULLSEYE_ALIAS_ANALYSIS="$alias_analysis"
    export BULLSEYE_ANDER_TIMEOUT="1200"

    set +e
    opt-18 -load-pass-plugin=/directed_fuzzing/Bullseye/libBullseyePass.so \
      -passes="bullseye" -disable-output $BULLSEYE_LOOPS_SIMPLIFIED

    exit_code=$?
    set -e

    case $exit_code in
      0)
        break
        ;;
      1)
        echo "Error: configuration error"
        exit 1
        ;;
      2)
        echo "Error: no path to the target"
        exit 2
        ;;
      3)
        echo "Error: target location not found"
        exit 3
        ;;
      101)
        # Only retry on 101, but only if there's another strategy to try
        continue
        ;;
      *)
        echo "Error: Bullseye analysis failed for unknown reason (code $exit_code)"
        exit $exit_code
        ;;
    esac
  done

  $COMPILER $BULLSEYE_LOOPS_SIMPLIFIED \
    /directed_fuzzing/Bullseye/libAFLDriver.a \
    $BULLSEYE_EXTRA_LINK_FLAGS $BULLSEYE_LINKAGE_FLAGS \
    -o $BULLSEYE_FUZZ_BIN

  exit_code=$?
  if [ $exit_code -ne 0 ] || [ ! -f "$BULLSEYE_FUZZ_BIN" ]; then
      echo "Error: Compilation failed for unknown reasons"
      exit $exit_code
  fi
popd
