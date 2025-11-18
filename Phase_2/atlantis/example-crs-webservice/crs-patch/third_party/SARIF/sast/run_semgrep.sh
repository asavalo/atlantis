#! /bin/bash -x

semgrep scan --dataflow-traces --sarif -o $OUT/semgrep.sarif