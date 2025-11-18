#!/bin/bash

source /directed_fuzzing/common.sh
pushd "$BULLSEYE_BUILD_DIR"

  # this is so that we respect the cpu assignment given to us from the controller
  export AFL_NO_AFFINITY=1
  export AFL_SKIP_CPUFREQ=1 # can test governors later
  echo core | tee /proc/sys/kernel/core_pattern

  # -Z is a must to use Bullseye input prioritization
  # BULLSEYE_FUZZER_FLAGS: you can pass any flags to fuzzer (i.e. timeout -t).
  # BULLSEYE_FUZZ_BIN_FLAGS: and here you pass the flags to binary being fuzzed.
  /directed_fuzzing/Bullseye/afl-fuzz \
    -i $BULLSEYE_INPUT_CORPUS \
    -o $BULLSEYE_FUZZ_OUT \
    -Z \
    $BULLSEYE_FUZZER_FLAGS \
    $BULLSEYE_DICTIONARY_ARGS \
    -- \
    $BULLSEYE_FUZZ_BIN \
    $BULLSEYE_FUZZ_BIN_FLAGS

popd
