#!/usr/bin/env bash
set -euo pipefail

# --- settings you can tweak ---
MODEL="${MODEL_NAME:-llama3.1:8b-instruct-q4_K_M}"
WS_IMAGE="${WS_IMAGE:-asavalo-atlantis-webservice}"   # your built image
NET="atlnet"
WORKERS="${WORKERS:-4}"
DEFAULT_OLLAMA_PORT=11434
DEFAULT_WS_BASE=8000

# --- helpers ---
free_port() { # find first free TCP port >= $1
  local p="$1"
  while ss -ltnH "( sport = :$p )" >/dev/null 2>&1; do p=$((p+1)); done
  echo "$p"
}
reuse_or_free() { # $1 container_name -> prints "reuse" or "remove"
  if docker ps -a --format '{{.Names}}' | grep -qx "$1"; then
    # If exiting or dead, remove; if running, reuse
    local st
    st="$(docker inspect -f '{{.State.Status}}' "$1" 2>/dev/null || echo 'missing')"
    if [[ "$st" == "running" ]]; then echo "reuse"; else echo "remove"; fi
  else
    echo "new"
  fi
}

echo "==> Ensuring docker network: ${NET}"
docker network create "${NET}" >/dev/null 2>&1 || true

# --- OLLAMA: reuse if already running; otherwise start on a free port ---
OLLAMA_NAME="ollama"
case "$(reuse_or_free "$OLLAMA_NAME")" in
  reuse)
    echo "==> Reusing existing Ollama container: $OLLAMA_NAME"
    OLLAMA_HOST_PORT="$(docker inspect -f '{{(index (index .NetworkSettings.Ports "11434/tcp") 0).HostPort}}' "$OLLAMA_NAME" 2>/dev/null || true)"
    if [[ -z "${OLLAMA_HOST_PORT:-}" ]]; then
      # not published? pick a free port and publish it
      OLLAMA_HOST_PORT="$(free_port "$DEFAULT_OLLAMA_PORT")"
      echo "==> Publishing Ollama on 127.0.0.1:${OLLAMA_HOST_PORT}"
      docker commit "$OLLAMA_NAME" tmp-ollama-repub >/dev/null
      docker rm -f "$OLLAMA_NAME" >/dev/null
      docker run -d --name "$OLLAMA_NAME" --network "$NET" \
        -p "127.0.0.1:${OLLAMA_HOST_PORT}:11434" \
        -e OLLAMA_HOST=0.0.0.0 --restart unless-stopped \
        tmp-ollama-repub >/dev/null
      docker image rm tmp-ollama-repub >/dev/null 2>&1 || true
    fi
    ;;
  remove)
    echo "==> Removing stopped Ollama container"
    docker rm -f "$OLLAMA_NAME" >/dev/null
    ;&
  new)
    OLLAMA_HOST_PORT="$(free_port "$DEFAULT_OLLAMA_PORT")"
    echo "==> Starting new Ollama on 127.0.0.1:${OLLAMA_HOST_PORT}"
    docker run -d --name "$OLLAMA_NAME" --network "$NET" \
      -p "127.0.0.1:${OLLAMA_HOST_PORT}:11434" \
      -e OLLAMA_HOST=0.0.0.0 \
      --restart unless-stopped \
      ollama/ollama:latest >/dev/null
    ;;
esac

echo "==> Ensuring model present: ${MODEL}"
docker exec -i "$OLLAMA_NAME" ollama pull "$MODEL" >/dev/null

# --- WORKERS: start atl-web-0..N on free ports (or reuse if already running) ---
declare -a WS_PORTS=()
for i in $(seq 0 $((WORKERS-1))); do
  C="atl-web-$i"
  case "$(reuse_or_free "$C")" in
    reuse)
      echo "==> Reusing $C"
      HP="$(docker inspect -f '{{(index (index .NetworkSettings.Ports "8000/tcp") 0).HostPort}}' "$C" 2>/dev/null || true)"
      if [[ -z "${HP:-}" ]]; then
        # republish to a free port
        HP="$(free_port "$((DEFAULT_WS_BASE+i))")"
        echo "   republishing $C on 127.0.0.1:$HP"
        docker commit "$C" tmp-$C-repub >/dev/null
        docker rm -f "$C" >/dev/null
        docker run -d --name "$C" --network "$NET" \
          -p "127.0.0.1:${HP}:8000" \
          -e OLLAMA_URL="http://ollama:11434" \
          -e MODEL_NAME="${MODEL}" \
          --restart unless-stopped \
          tmp-$C-repub uvicorn main:app --host 0.0.0.0 --port 8000 >/dev/null
        docker image rm tmp-$C-repub >/dev/null 2>&1 || true
      fi
      WS_PORTS+=("${HP}")
      ;;
    remove)
      docker rm -f "$C" >/dev/null
      ;&
    new)
      HP="$(free_port "$((DEFAULT_WS_BASE+i))")"
      echo "==> Starting $C on 127.0.0.1:${HP}"
      docker run -d --name "$C" --network "$NET" \
        -p "127.0.0.1:${HP}:8000" \
        -e OLLAMA_URL="http://ollama:11434" \
        -e MODEL_NAME="${MODEL}" \
        --restart unless-stopped \
        "${WS_IMAGE}" \
        uvicorn main:app --host 0.0.0.0 --port 8000 >/dev/null
      WS_PORTS+=("${HP}")
      ;;
  esac
done

echo "==> Health checks"
for idx in "${!WS_PORTS[@]}"; do
  p="${WS_PORTS[$idx]}"
  printf "  worker[%d] " "$idx"
  curl -sf "http://127.0.0.1:${p}/healthz" >/dev/null && echo "OK on ${p}" || echo "NOT READY on ${p}"
done

echo "==> Summary"
echo "  Ollama:            http://127.0.0.1:${OLLAMA_HOST_PORT}"
for idx in "${!WS_PORTS[@]}"; do
  echo "  atl-web-${idx}:     http://127.0.0.1:${WS_PORTS[$idx]}"
done

# Export hints for your runner (print so you can copy)
echo
echo "Export these for your repo runner:"
echo "  export OLLAMA_PORT=${OLLAMA_HOST_PORT}"
echo -n "  export WORKER_PORTS=\""; printf "%s " "${WS_PORTS[@]}"; echo "\""
