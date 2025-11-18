#!/bin/bash

set -e

if [ -z "$TARGET_NAME" ]; then
    echo "TARGET_NAME is not set"
    exit 1
fi

IFS=',' read -ra CORE_LIST <<< "$CORES"
CORE_NUM=${#CORE_LIST[@]}

echo "Cleaning up"
rm -rf /root/fuzzilli/fuzz_root/old_corpus
rm -rf /root/fuzzilli/fuzz_root/settings.json
rm -rf /root/fuzzilli/fuzz_root/stats

if [ "$TARGET_NAME" == "quickjs" ]; then
    echo "Fuzzing QuickJS"
    taskset -c $CORES /root/fuzzilli/Fuzzilli --jobs=$CORE_NUM --profile=qjs --storagePath=/root/fuzzilli/fuzz_root --resume /root/fuzzilli/Targets/QJS/qjs/qjs
elif [ "$TARGET_NAME" == "spidermonkey" ]; then
    echo "Fuzzing SpiderMonkey"
    #/root/fuzzilli/Fuzzilli --profile=spidermonkey--storagePath=/root/fuzzilli/fuzz_root --resume /root/fuzzilli/Targets/njs/njs/build/njs_fuzzilli
elif [ "$TARGET_NAME" == "njs" ]; then
    echo "Fuzzing njs"
    taskset -c $CORES /root/fuzzilli/Fuzzilli --jobs=$CORE_NUM --profile=njs --storagePath=/root/fuzzilli/fuzz_root --resume /root/fuzzilli/Targets/njs/njs/build/njs_fuzzilli
fi
