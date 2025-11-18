#!/bin/bash

export TMPFS_ROOT=${ENSEMBLER_TMPFS:-/tmpfs}

if command -v start-docker.sh 2>&1 >/dev/null
then
    echo "[Ensembler] Ensuring DinD is running"
    start-docker.sh
else
    echo "[Ensembler] start-docker.sh not found, skipping"
fi

while ! docker info > /dev/null 2>&1; do
    echo "Waiting for Docker to be ready..."
    sleep 1
done

# cleanup DinD state to be safe
docker system prune -af
docker volume prune -f

# Create TMPFS_ROOT only if it doesn't exist
if [ ! -d "$TMPFS_ROOT" ]; then
    mkdir "$TMPFS_ROOT"
    # mount tmpfs -t tmpfs $TMPFS_ROOT
fi

mkdir -p $TMPFS_ROOT/seeds
mkdir -p $TMPFS_ROOT/feedback
mkdir -p $TMPFS_ROOT/tmp

PYTHONUNBUFFERED=1 /venv/bin/python3 -m seed_ensembler \
    --interface-mode=kafka \
    --execution-mode=docker \
    --seeds-input-dir=$TMPFS_ROOT/seeds \
    --feedback-output-dir=$TMPFS_ROOT/feedback \
    --temp-dir=$TMPFS_ROOT/tmp \
    --worker-pool-size=10 \
    --duplicate-seeds-cache-size=100000 \
    --no-inotify
