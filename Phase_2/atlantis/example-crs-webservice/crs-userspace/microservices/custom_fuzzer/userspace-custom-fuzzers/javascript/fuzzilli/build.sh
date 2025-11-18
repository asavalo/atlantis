#!/bin/bash

set -e

if [ -z "$TARGET_NAME" ]; then
    echo "TARGET_NAME is not set"
    exit 1
fi

if [ "$TARGET_NAME" == "quickjs" ]; then
    echo "Building QuickJS"
    cd /root/fuzzilli/Targets/QJS
    ./setup.sh /src && ./fuzzbuild.sh
elif [ "$TARGET_NAME" == "spidermonkey" ]; then
    echo "Building SpiderMonkey"
    cd /root/fuzzilli/Targets/Spidermonkey
    ./setup.sh /src && ./fuzzbuild.sh
elif [ "$TARGET_NAME" == "njs" ]; then
    echo "Building njs"
    cd /root/fuzzilli/Targets/njs
    ./setup.sh /src && ./fuzzbuild.sh
fi

cd /root/fuzzilli