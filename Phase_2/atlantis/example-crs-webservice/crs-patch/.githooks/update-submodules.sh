#!/bin/sh
if ! git submodule update; then
    git submodule update --init --remote || echo "Failed to update submodules"
fi
