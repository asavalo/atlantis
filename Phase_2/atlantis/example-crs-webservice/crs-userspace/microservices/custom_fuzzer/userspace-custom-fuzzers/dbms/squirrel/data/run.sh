#!/bin/bash

HARNESS_NAME=$1
DBMS=$2
IDX=$3

export ASAN_OPTIONS="$ASAN_OPTIONS:abort_on_error=1:symbolize=0:detect_odr_violation=0:"
export MSAN_OPTIONS="$MSAN_OPTIONS:exit_code=86:symbolize=0"
export UBSAN_OPTIONS="$UBSAN_OPTIONS:symbolize=0"
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1
export AFL_FAST_CAL=1
export AFL_CMPLOG_ONLY_NEW=1
export AFL_FORKSRV_INIT_TMOUT=30000
export AFL_IGNORE_PROBLEMS=1
export AFL_IGNORE_UNKNOWN_ENVS=1
export AFL_CUSTOM_MUTATOR_ONLY=1
export AFL_CUSTOM_MUTATOR_LIBRARY=/root/build/lib${DBMS}_mutator.so
export AFL_DISABLE_TRIM=1
export AFL_AUTORESUME=1
export AFL_QUIET=1
export AFL_NO_UI=1
export AFL_FORKSRV_INIT_TMOUT=1000000
export SQUIRREL_CONFIG=/root/data/config_${DBMS}.yml
# FIXME: ignore core_idx for now
/out/afl-fuzz -i /root/data/fuzz_root/input -o /root/data/fuzz_root/output /out/${HARNESS_NAME} 2>&1 | grep -v -e "WARNING" -e "dry run"