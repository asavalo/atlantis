#!/bin/bash

__REAL_MAVEN_REPO="$HOME/.m2/repository"
__SHARED_MAVEN_REPO="/work/mavencache"

# If we use mavencache, redirect the maven local repository to the shared cache
if [ ! -L "$__REAL_MAVEN_REPO" ]; then
    mkdir -p "$(dirname "$__REAL_MAVEN_REPO")"

    # If there is an existing local repository, migrate it to the shared cache
    if [ -d "$__REAL_MAVEN_REPO" ] && [ ! -L "$__REAL_MAVEN_REPO" ]; then
        rsync -a "$__REAL_MAVEN_REPO/" "$__SHARED_MAVEN_REPO/"
    fi

    # At this point, the local repository should be non-existent
    rm -rf "$__REAL_MAVEN_REPO"
    ln -sf "$__SHARED_MAVEN_REPO" "$__REAL_MAVEN_REPO"
fi

unset __REAL_MAVEN_REPO
unset __SHARED_MAVEN_REPO
