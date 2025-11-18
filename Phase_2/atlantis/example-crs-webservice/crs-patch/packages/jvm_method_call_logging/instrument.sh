#!/bin/bash

rm -rf /work/method_call_logging
cp -R /work/jvm_method_call_logging /work/method_call_logging
cd /work/method_call_logging/instrumenter

if [[ -n $MVN ]]; then
    echo "Using MVN from environment variable"
    echo "MVN is set to: $MVN"
    $MVN clean package
elif command -v mvn >/dev/null 2>&1; then
    echo "Using system-installed Maven"
    mvn clean package
else
    echo "Maven is not available"
    exit 1
fi

cd ..

python3 instrument.py
