#!/bin/bash


for target in SQLite MySQL PostgreSQL
do
  mkdir -p "/home/fuzzuser/sqlright/$target/Bug_Analysis/bug_samples"
  cd "/home/fuzzuser/sqlright/$target/src" && make -j
  ls "/home/fuzzuser/sqlright/$target/src"
  cp "/home/fuzzuser/sqlright/$target/src/afl-fuzz" "/home/fuzzuser/sqlright/$target/fuzz_root/afl-fuzz"
done
