#!/bin/bash
set -e

cd `dirname $0`
python3 visualize-symstate-result.py \
	-t aixcc/c/asc-nginx \
	-H pov_harness \
	-o output \
	-m $(realpath ../) \
	../eval-asc-nginx

