#!/usr/bin/env bash
set -euo pipefail

# ----------------------------
# Config (override via env)
# ----------------------------
# ----------------------------
MODEL_NAME="${MODEL_NAME:-llama3.1:8b-instruct-q4_K_M}"
APP_PORT="${APP_PORT:-8000}"
OLLAMA_PORT="${OLLAMA_PORT:-11434}"
SERVICE_DIR="${SERVICE_DIR:-example-crs-webservice}"
ARCH_NOTE="example-crs-architecture"
FORCE="false"

if [[ "${1:-}" == "--force" ]]; then
  FORCE="true"
fi

# ----------------------------
# ----------------------------
# Helpers
# ----------------------------
# ----------------------------
have() { command -v "$1" >/dev/null 2>&1; }

write_file() {
  local path="$1"; shift
  local content="$*"
  if [[ -f "$path" && "$FORCE" != "true" ]]; then
    echo "SKIP    $path (exists; use --force to overwrite)"
  else
    mkdir -p "$(dirname "$path")"
    printf "%s" "$content" > "$path"
    echo "WROTE   $path"
  fi
}

append_unique() {
  local path="$1"; shift
  local line="$*"
  touch "$path"
  grep -qxF "$line" "$path" || echo "$line" >> "$path"
}

# ----------------------------
# ----------------------------
# Pre-flight checks
# ----------------------------
# ----------------------------
echo "==> Preflight checks"
DC="docker compose"
have docker || { echo "ERROR: docker not found"; exit 1; }
have curl   || { echo "ERROR: curl not found"; exit 1; }

# docker compose v2+ check
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif have docker-compose; then
  DC="docker-compose"
else
  DC="docker-compose" #echo "ERROR: docker compose not found"
  #exit 1
fi

# ----------------------------
# ----------------------------
# Write docker-compose.yml
# ----------------------------
# ----------------------------
echo "==> Writing docker-compose.yml"
write_file "docker-compose.yml" "$(cat <<'YAML'
version: "3.9"

services:
  ollama:
    image: ollama/ollama:latest
    container_name: ollama
    ports:
      - "127.0.0.1:11434:11434"
    volumes:
      - ollama_models:/root/.ollama
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:11434/api/tags"]
      interval: 10s
      timeout: 3s
      retries: 20
    restart: unless-stopped
    # GPU (optional):
    # deploy:
    #   resources:
    #     reservations:
    #       devices:
    #         - capabilities: ["gpu"]
    #           driver: nvidia

  atlantis-webservice:
    build:
      context: ./example-crs-webservice
      dockerfile: Dockerfile
    container_name: atlantis-webservice
    depends_on:
      ollama:
        condition: service_healthy
    environment:
      AUTH_MODE: "disabled"
      PROVIDER: "ollama"
      OLLAMA_BASE_URL: "http://ollama:11434"
      OLLAMA_MODEL: "${MODEL_NAME}"
      LLM_TIMEOUT_MS: "180000"
      LLM_MAX_TOKENS: "2048"
    ports:
      - "127.0.0.1:8000:8000"
    restart: unless-stopped

volumes:
  ollama_models:
YAML
)"

# ----------------------------
# ----------------------------
# Webservice skeleton & files
# ----------------------------
# ----------------------------
echo "==> Laying down minimal webservice files under $SERVICE_DIR/"

# Dockerfile
write_file "$SERVICE_DIR/Dockerfile" "$(cat <<'DOCKER'
FROM python:3.11-slim

WORKDIR /app
COPY . /app

# If your project already has requirements.txt or pyproject, swap this block accordingly:
RUN pip install --no-cache-dir fastapi uvicorn requests

EXPOSE 8000
ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
DOCKER
)"

# Minimal FastAPI app (only created if missing, unless --force)
write_file "$SERVICE_DIR/main.py" "$(cat <<'PY'
from fastapi import FastAPI, Depends
from pydantic import BaseModel
from aixcc.auth import require_user
from aixcc.providers.factory import chat, generate, healthcheck

app = FastAPI()

class CRSRequest(BaseModel):
    prompt: str | None = None
    messages: list[dict] | None = None
    stream: bool = False

@app.get("/healthz")
def healthz():
    return {"ok": True, "llm": healthcheck()}

@app.post("/v1/crs/run")
def run_crs(req: CRSRequest, user=Depends(require_user)):
    messages = req.messages or [{"role":"user","content": req.prompt or ""}]
    out = chat(messages, stream=False)
    return {"output": out.get("content","")}
PY
)"

# Auth bypass
write_file "$SERVICE_DIR/aixcc/auth.py" "$(cat <<'PY'
import os
from fastapi import HTTPException

AUTH_MODE = os.getenv("AUTH_MODE", "disabled").lower()

def require_user():
    if AUTH_MODE == "disabled":
        return {"user":"local"}
    raise HTTPException(status_code=403, detail="Auth disabled or unsupported in local mode.")
PY
)"

# Provider factory
write_file "$SERVICE_DIR/aixcc/providers/factory.py" "$(cat <<'PY'
import os
from . import ollama_client

PROVIDER = os.getenv("PROVIDER", "ollama").lower()

def chat(messages, **kwargs):
    if PROVIDER == "ollama":
        return ollama_client.chat(messages, **kwargs)
    raise RuntimeError(f"Unknown PROVIDER={PROVIDER}")

def generate(prompt, **kwargs):
    if PROVIDER == "ollama":
        return ollama_client.generate(prompt, **kwargs)
    raise RuntimeError(f"Unknown PROVIDER={PROVIDER}")

def embeddings(texts):
    if PROVIDER == "ollama":
        return ollama_client.embeddings(texts)
    raise RuntimeError(f"Unknown PROVIDER={PROVIDER}")

def healthcheck():
    if PROVIDER == "ollama":
        return ollama_client.healthcheck()
    return False
PY
)"

# Ollama client shim
write_file "$SERVICE_DIR/aixcc/providers/ollama_client.py" "$(cat <<'PY'
import os, json, requests
from typing import List, Optional, Dict, Any

OLLAMA_BASE = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b-instruct-q4_K_M")
TIMEOUT = float(os.getenv("LLM_TIMEOUT_MS", "180000")) / 1000.0
MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "2048"))

def _headers() -> Dict[str, str]:
    return {"Content-Type": "application/json"}

def healthcheck() -> bool:
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
        r.raise_for_status()
        return True
    except Exception:
        return False

def chat(
    messages: List[Dict[str, str]],
    stream: bool = False,
    temperature: float = 0.2,
    top_p: float = 0.9,
    stop: Optional[List[str]] = None,
    **kwargs: Any,
) -> Any:
    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": bool(stream),
        "options": {
            "temperature": temperature,
            "top_p": top_p,
            "num_predict": MAX_TOKENS,
        },
    }
    if stop: payload["stop"] = stop
    url = f"{OLLAMA_BASE}/api/chat"

    if stream:
        with requests.post(url, headers=_headers(), data=json.dumps(payload), timeout=TIMEOUT, stream=True) as r:
            r.raise_for_status()
            for line in r.iter_lines(decode_unicode=True):
                if not line: continue
                try: obj = json.loads(line)
                except Exception: continue
                if "message" in obj and "content" in obj["message"]:
                    yield obj["message"]["content"]
                if obj.get("done"): break
        return
    else:
        r = requests.post(url, headers=_headers(), data=json.dumps(payload), timeout=TIMEOUT)
        r.raise_for_status()
        obj = r.json()
        return {"content": obj.get("message", {}).get("content", "")}

def generate(prompt: str, stream: bool = False, **kwargs: Any) -> Any:
    payload = {"model": OLLAMA_MODEL, "prompt": prompt, "stream": bool(stream), "options": {"num_predict": MAX_TOKENS}}
    url = f"{OLLAMA_BASE}/api/generate"
    if stream:
        with requests.post(url, headers=_headers(), data=json.dumps(payload), timeout=TIMEOUT, stream=True) as r:
            r.raise_for_status()
            for line in r.iter_lines(decode_unicode=True):
                if not line: continue
                try: obj = json.loads(line)
                except Exception: continue
                if "response" in obj: yield obj["response"]
                if obj.get("done"): break
        return
    else:
        r = requests.post(url, headers=_headers(), data=json.dumps(payload), timeout=TIMEOUT)
        r.raise_for_status()
        return {"text": r.json().get("response", "")}

def embeddings(texts: List[str]) -> List[List[float]]:
    dim = 256
    return [[0.0] * dim for _ in texts]
PY
)"

# Make sure package imports work (namespace dirs)
append_unique "$SERVICE_DIR/aixcc/__init__.py" ""
append_unique "$SERVICE_DIR/aixcc/providers/__init__.py" ""

# ----------------------------
# ----------------------------
# Bring up stack
# ----------------------------
# ----------------------------
echo "==> Building & starting containers"
$DC up -d --build

# ----------------------------
# ----------------------------
# Pull model & warm up
# ----------------------------
# ----------------------------
echo "==> Ensuring model is pulled: ${MODEL_NAME}"
docker exec -i ollama ollama pull "${MODEL_NAME}"

echo "==> Warm-up generate"
curl -s "http://127.0.0.1:${OLLAMA_PORT}/api/generate" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"${MODEL_NAME}\",\"prompt\":\"Say ready.\",\"stream\":false}" >/dev/null || true

# ----------------------------
# ----------------------------
# Health checks
# ----------------------------
# ----------------------------
echo "==> Checking service health"
sleep 2
curl -sf "http://127.0.0.1:${APP_PORT}/healthz" || {
  echo
  echo "WARN: Webservice health check failed. Run: docker logs atlantis-webservice"
  exit 1
}

echo
echo "✅ Setup complete."
echo "• Ollama:        http://127.0.0.1:${OLLAMA_PORT}"
echo "• Webservice:    http://127.0.0.1:${APP_PORT}"
echo
echo "Try a CRS run:"
echo "curl -s http://127.0.0.1:${APP_PORT}/v1/crs/run -H 'Content-Type: application/json' -d '{\"prompt\":\"Hello\"}' | jq"
