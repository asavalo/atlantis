#!/bin/bash
set -e
cd "$(dirname "$0")" 
rm -rf LibAFL/target
rm -rf concolic_executor/target
rm -rf concolic_executor/libsymcc-rt.so
rm -rf concolic_executor/symcc-venv
rm -rf z3/build
rm -rf atlantis_cc/*_wrapper
rm -rf atlantis_cc/target
rm -rf glib-2.66/_build
rm -rf glib-2.66/meson-venv
rm -rf symcc-pass/build
rm -rf symcc-pass/build-obsessive
rm -rf symqemu-multilang/build
rm -rf symqemu-multilang/symqemu-venv
rm -rf symcc-fuzzing-engine/build
rm -rf symcc-fuzzing-engine/libSymCCFuzzingEngine.a
