#!/bin/bash

GITHUB_TOKEN=$(cat .github_token)
GITHUB_REPOSITORY="Team-Atlanta/crete"
WORKFLOW_NAME="benchmark.yaml"
BRANCH="main"
INPUT_MODULE=""
INPUT_TARGET='./scripts/benchmark/lite/*.toml'

if [ -z "$GITHUB_TOKEN" ]; then
    echo "Please set your Github PAT (Personal Access Token) in .github_token file"
    exit 1
fi

curl -X POST \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github.v3+json" \
    https://api.github.com/repos/$GITHUB_REPOSITORY/actions/workflows/$WORKFLOW_NAME/dispatches \
    -d '{
        "ref":"'$BRANCH'",
        "inputs": {
            "module": "'$INPUT_MODULE'",
            "target": "'$INPUT_TARGET'"
        }
    }'
