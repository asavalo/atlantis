# !/bin/bash

set -e

# If repo directory does not exist, create it
if [ ! -d "./repo" ]; then
    mkdir ./repo
fi

# Jenkins
ID="jenkins"
# Check if the directory exists
if [ -d "./repo/$ID" ]; then
    echo "Directory exists. $ID"
else
    git clone https://github.com/Team-Atlanta/cp-java-jenkins-source ./repo/$ID
fi