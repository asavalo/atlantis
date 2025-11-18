#!/bin/bash

echo 0 | tee /proc/sys/kernel/randomize_va_space
sysctl kernel.perf_event_paranoid=1

if [[ $# -gt 0 ]]; then
  exec "$@"
else
  exec /bin/bash
fi
