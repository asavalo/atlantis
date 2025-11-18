#!/bin/bash

set -e

cd `dirname $0`

if [ "$CARGO_BUILD_FLAGS" == "--release" ]; then
    export SERVER_PATH=target/release/concolicd
    export CLIENT_PATH=target/release/concolic_client
else 
    export SERVER_PATH=target/debug/concolicd
    export CLIENT_PATH=target/debug/concolic_client
fi

cargo build $CARGO_BUILD_FLAGS

cp $SERVER_PATH concolicd
