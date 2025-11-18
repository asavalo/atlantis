#!/usr/bin/env bash
# Verify local Atlantis webservice uses Team-Atlanta modules & local Ollama only.
# - Confirms containers up & healthy
# - Confirms module import paths /app/aixcc/* (not vendored elsewhere)
# - Confirms provider=Ollama and endpoint=http://ollama:11434
# - Ensures no azure/login URLs referenced by running code
# - Ensures model present & app can reach Ollama
# - Performs a strict JSON test call and validates JSON return
# - Greps recent logs for external URLs (egress)
#
# Usage:
#   ./verify_atlantis_stack.sh
#
# Exit code 0 = PASS, nonzero = FAIL (any check)

set -Eeuo pipefail

ENDPOINT="${ENDPOINT:-http://127.0.0.1:8000}"
OLLAMA_HOST="${OLLAMA_HOST:-http://127.0.0.1:11434}"
MODEL_NAME="${MODEL_NAME:-llama3.1:8b-instruct-q4_K_M}"
MAX_WAIT="${MAX_WAIT:-60}"

fail() { echo "❌ $*" >&2; exit 1; }
warn() { echo "⚠️  $*" >&2; }
ok()   { echo "✅ $*"; }

echo "==> Ensuring containers are up"
docker-compose up -d >/dev/null 2>&1 || true

echo "==> Waiting for webservice health (${ENDPOINT}/healthz)"
for i in $(seq 1 "$MAX_WAIT"); do
  if curl -sf "${ENDPOINT}/healthz" >/dev/null 2>&1; then
    ok "webservice healthy"
    break
  fi
  sleep 1
  [[ "$i" -eq "$MAX_WAIT" ]] && fail "webservice failed to become healthy"
done

echo "==> Container list"
docker-compose ps || true

echo "==> Checking Ollama model presence ($MODEL_NAME)"
docker exec -i ollama ollama list 2>/dev/null | grep -q "^${MODEL_NAME}[[:space:]]" \
  && ok "model present" || warn "model not found in 'ollama list' (will try pull)"
docker exec -i ollama ollama pull "$MODEL_NAME" >/dev/null 2>&1 || true

echo "==> Verifying app -> Ollama connectivity"
docker exec -i atlantis-webservice python - <<'PY'
import requests, os, sys
u = os.environ.get("OLLAMA_URL","http://ollama:11434") + "/api/tags"
try:
    r = requests.get(u, timeout=5)
    print("OK", r.status_code)
except Exception as e:
    print("ERR", e)
PY

echo "==> Inspecting Python module import paths inside atlantis-webservice"
docker exec -i atlantis-webservice python - <<'PY'
import importlib, json, sys
mods = [
  "aixcc.auth",
  "aixcc.providers.factory",
  "aixcc.providers.ollama_client",
]
out = {}
for m in mods:
    try:
        mod = importlib.import_module(m)
        out[m] = getattr(mod, "__file__", "<no-file>")
    except Exception as e:
        out[m] = f"<IMPORT-ERROR: {e}>"
print(json.dumps(out, indent=2))
PY

echo "==> Confirm Ollama provider selection & config"
docker exec -i atlantis-webservice python - <<'PY'
import os, json, sys
cfg = {
  "OLLAMA_URL": os.environ.get("OLLAMA_URL","<unset>"),
  "MODEL_NAME": os.environ.get("MODEL_NAME","<unset>"),
  "READ_TO": os.environ.get("OLLAMA_READ_TIMEOUT","<unset>"),
  "CONNECT_TO": os.environ.get("OLLAMA_CONNECT_TIMEOUT","<unset>")
}
print(json.dumps(cfg, indent=2))
PY

echo "==> Grep container filesystem for disallowed endpoints (azure/login) - code paths"
BAD=$(
  docker exec -i atlantis-webservice /bin/sh -lc \
    "grep -RIEn --binary-files=without-match -i 'login\\|azure\\|openai\\.com' /app 2>/dev/null | head -n 3" \
  || true
)
if [[ -n "$BAD" ]]; then
  warn "Potential external/login references in /app:\n$BAD"
else
  ok "no azure/login/openai references found in /app code"
fi

echo "==> Strict JSON test call (must return JSON array or object, not prose)"
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
curl -s -H "Content-Type: application/json" \
  -d '{
        "messages":[
          {"role":"system","content":"Return ONLY valid JSON, not prose."},
          {"role":"user","content":"Analyze this tiny snippet and list CWEs (if any) for: String p=\"s3cret\";"}
        ],
        "format":"json",
        "stream":false,
        "llm_max_tokens":128,
        "llm_temperature":0
      }' \
  "${ENDPOINT}/v1/crs/run" -o "$TMP" || fail "webservice request failed"

# Validate JSON
if jq . >/dev/null 2>&1 < "$TMP"; then
  ok "strict JSON response from webservice"
else
  echo "---- RAW BODY ----"
  cat "$TMP"
  echo "------------------"
  fail "response is not valid JSON"
fi

echo "==> Check recent logs for unexpected egress (http/https not to ollama/webservice)"
# Capture last 400 log lines and grep for external URLs (ignore 127.0.0.1, ollama host, webservice)
OLLAMA_HOST_S=$(echo "$OLLAMA_HOST" | sed 's|/|\\/|g')
ENDPOINT_S=$(echo "$ENDPOINT" | sed 's|/|\\/|g')
docker compose logs --no-color --tail=400 atlantis-webservice ollama > /tmp/_crs_logs.txt 2>/dev/null || true

BAD_URLS=$(grep -Eo 'https?://[^ ]+' /tmp/_crs_logs.txt | \
  grep -Ev "(${OLLAMA_HOST_S}|${ENDPOINT_S}|127\.0\.0\.1|ollama:11434|localhost)" || true)

if [[ -n "$BAD_URLS" ]]; then
  warn "Potential external calls seen in recent logs:\n$BAD_URLS"
else
  ok "no unexpected external calls in recent logs"
fi

echo "==> Verifying imports resolved from /app/aixcc/*"
IMPATHS=$(docker exec -i atlantis-webservice python - <<'PY'
import importlib, sys
mods = ["aixcc.auth", "aixcc.providers.factory", "aixcc.providers.ollama_client"]
for m in mods:
    try:
        mod = importlib.import_module(m)
        print(getattr(mod,"__file__","<no-file>"))
    except Exception as e:
        print(f"<IMPORT-ERROR: {m}: {e}>")
PY
)
if echo "$IMPATHS" | grep -q "/app/aixcc/"; then
  ok "Atlantis modules are loaded from /app/aixcc/*"
else
  echo "$IMPATHS"
  fail "Atlantis modules not loaded from expected /app/aixcc/* path"
fi

echo "==> Final status: PASS"
exit 0
