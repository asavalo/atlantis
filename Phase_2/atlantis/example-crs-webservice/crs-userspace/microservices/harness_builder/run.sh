#!/bin/bash

if command -v start-docker.sh 2>&1 >/dev/null
then
    echo "[Harness Builder] Ensuring DinD is running"
    start-docker.sh
else
    echo "[Harness Builder] start-docker.sh not found, skipping"
fi

while ! docker info > /dev/null 2>&1; do
    echo "Waiting for Docker to be ready..."
    sleep 1
done

# cleanup DinD state to be safe
docker system prune -af
docker volume prune -f

PYTHONUNBUFFERED=1 /venv/bin/python3 -m harness_builder
