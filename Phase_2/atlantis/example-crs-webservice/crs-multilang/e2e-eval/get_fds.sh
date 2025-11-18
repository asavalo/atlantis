#!/bin/bash

for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  fd_count=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
  if [ "$fd_count" -ge 100 ]; then
    cmd=$(ps -p $pid -o comm=)
    echo "$pid ($cmd): $fd_count"
  fi
done
