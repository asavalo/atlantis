# ~/reset_and_start_4workers.sh
set -euo pipefail

# --- settings ---
MODEL="${MODEL_NAME:-llama3.1:8b-instruct-q4_K_M}"
NET="atlnet"
OLLAMA_NAME="ollama"
OLLAMA_HOST_PORT="11434"
WS_IMAGE="${WS_IMAGE:-asavalo-atlantis-webservice}"   # your built image tag
PORT_BASE=8000                                        # workers on 8000..8003
WORKERS=4

echo "==> Cleaning conflicting containers (safe no-op if none)"
docker rm -f "${OLLAMA_NAME}" >/dev/null 2>&1 || true
for i in $(seq 0 $((WORKERS-1))); do docker rm -f "atl-web-${i}" >/dev/null 2>&1 || true; done

echo "==> Ensuring docker network: ${NET}"
docker network create "${NET}" >/dev/null 2>&1 || true

echo "==> Starting single shared Ollama on ${OLLAMA_HOST_PORT}"
docker run -d --name "${OLLAMA_NAME}" --network "${NET}" \
  -p "127.0.0.1:${OLLAMA_HOST_PORT}:11434" \
  -e OLLAMA_HOST=0.0.0.0 \
  --restart unless-stopped \
  ollama/ollama:latest >/dev/null

echo "==> Pulling model: ${MODEL}"
docker exec -i "${OLLAMA_NAME}" ollama pull "${MODEL}"

echo "==> Starting ${WORKERS} Atlantis workers pointing at ollama:${OLLAMA_HOST_PORT}"
for i in $(seq 0 $((WORKERS-1))); do
  HP=$((PORT_BASE+i))
  echo "  -> atl-web-${i} on http://127.0.0.1:${HP}"
  docker run -d --name "atl-web-${i}" --network "${NET}" \
    -p "127.0.0.1:${HP}:8000" \
    -e OLLAMA_URL="http://ollama:11434" \
    -e MODEL_NAME="${MODEL}" \
    --restart unless-stopped \
    "${WS_IMAGE}" \
    uvicorn main:app --host 0.0.0.0 --port 8000 >/dev/null
done

echo "==> Health checks"
for i in $(seq 0 $((WORKERS-1))); do
  HP=$((PORT_BASE+i))
  printf "  worker[%d] " "$i"
  curl -sf "http://127.0.0.1:${HP}/healthz" >/dev/null && echo "OK on ${HP}" || echo "NOT READY on ${HP}"
done

echo "==> Containers"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E 'ollama|atl-web' || true

cat <<'TIP'

Next steps:

• Run your NiFi scan using the 4-worker script you used for Accumulo, just point it at ~/nifi.
  Example:
    WORKERS=4 PORT_OFFSET=0 \
    ~/scan_accumulo_g6e12x_adaptive.sh \
      ~/nifi \
      ~/multilang_nifi_findings.jsonl

• If that script still tries to start its own Ollama, disable that in the script
  (leave Ollama management to this launcher).

• Tail logs (pick any worker):
    docker logs -f atl-web-0
  Or Ollama:
    docker logs -f ollama

• If you need to combine artifacts after a run (when a /tmp/tmp.*/vuln_by_file exists),
  you can do something like:
    ART="$(ls -d /tmp/tmp.*/vuln_by_file | tail -1)" || true
    echo "$ART"
    # (use your combiner or cat the JSONL your runner produced)

TIP
