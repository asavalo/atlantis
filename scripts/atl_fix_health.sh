#!/usr/bin/env bash
set -euo pipefail

API="http://127.0.0.1:8000"
MODEL_NAME="${MODEL_NAME:-llama3.1:8b-instruct-q4_K_M}"

# Pick docker compose (v2 or v1)
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
else
  COMPOSE="docker-compose"
fi

echo "==> Containers (before)"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E 'ollama|atlantis-webservice' || true

# Ensure containers exist & are up (idempotent if you already have them running)
# If you use a compose file, run in its directory; otherwise just restart by name.
if ${COMPOSE} ps >/dev/null 2>&1; then
  echo "==> Bringing up via compose"
  ${COMPOSE} up -d
fi

# If containers not present via compose, try to start existing ones (no-op if running)
docker start ollama 2>/dev/null || true
docker start atlantis-webservice 2>/dev/null || true

echo "==> Pull/ensure model in Ollama"
if docker ps --format '{{.Names}}' | grep -q '^ollama$'; then
  docker exec -i ollama ollama pull "${MODEL_NAME}" || true
else
  echo "WARN: ollama container not found"
fi

echo "==> Quick connectivity checks"
set +e
docker exec -i atlantis-webservice curl -s http://ollama:11434/api/tags | head -c 200 && echo
docker exec -i ollama ollama list || true
set -e

echo "==> Wait for webservice health"
for i in {1..60}; do
  if curl -sf "${API}/healthz" >/dev/null; then
    echo "OK webservice healthy"
    break
  fi
  sleep 2
  [[ $i -eq 60 ]] && { echo "ERROR: webservice not healthy"; 
    echo "==> Last 200 lines of logs (webservice)"; docker logs --tail=200 atlantis-webservice || true
    echo "==> Last 200 lines of logs (ollama)"; docker logs --tail=200 ollama || true
    exit 1; }
done

echo "==> Containers (after)"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E 'ollama|atlantis-webservice' || true

echo "All set."
