# !/bin/bash

set -e

# If repo directory does not exist, create it
if [ ! -d "./repo" ]; then
    mkdir ./repo
fi

# asc-nginx
ID="asc-nginx"
# Check if the directory exists
if [ -d "./repo/$ID" ]; then
    echo "Directory exists. $ID"
else
    git clone https://github.com/aixcc-public/challenge-004-nginx-source ./repo/$ID
fi