#!/bin/bash

set -e

cd /root/fuzzilli/Targets/QJS/qjs

make CONFIG_ASAN=y