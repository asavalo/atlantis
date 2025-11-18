#!/bin/bash
set -e

cd /root/fuzzilli/Targets/njs/njs
LD=clang ./configure --cc=clang --cc-opt="-g -fsanitize-coverage=trace-pc-guard" --ld-opt="-L/usr/lib/clang/17/lib/linux -lclang_rt.profile-x86_64"
make njs_fuzzilli