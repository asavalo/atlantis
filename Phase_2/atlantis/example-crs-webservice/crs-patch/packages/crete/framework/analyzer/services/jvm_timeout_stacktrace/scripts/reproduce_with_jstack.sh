#!/bin/bash

harness_name=$1
output_path=${2:-"/out/jstack.txt"}

rm -f $output_path

find_target_pid() {
    ps aux | grep "jazzer" | grep -v grep | awk '{print $2}'
}

reproduce $harness_name -runs=100 > /dev/null 2>&1 &

sleep 2

for i in {1..30}; do
    target_pid=$(find_target_pid)
    if [ -z "$target_pid" ]; then
        echo "Jazzer exited or not found"
        exit 0
    fi
    echo "Jazzer is still running. Dumping jstack..."
    jstack $target_pid > $output_path
    sleep 1
done
