# Function Call Logger LLVM Pass

## Description

This is a simple LLVM pass that logs function calls with file name, function name, and line number.
With this pass, we can track recent call trace before the crash.
The log will be stored in `/work/call_trace.log`.

## How to build

```bash
$ docker run --rm -v $(pwd):/app -w /app ghcr.io/aixcc-finals/base-builder /app/build.sh
```

Or you can build inside the CP docker. (More recommended)