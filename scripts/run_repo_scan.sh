#!/usr/bin/env bash
# Drives a full repo CWE scan using the strict scanner
# Usage:
#   ./run_repo_scan.sh <repo_dir> "<focus>" <out.json>
# Example:
#   ./run_repo_scan.sh ~/accumulo \
#     "access control, authentication, authorization, secrets handling" \
#     ~/accumulo_full_repo.json

set -Eeuo pipefail

REPO="${1:-}"; FOCUS="${2:-security vulnerabilities}"; OUT="${3:-repo_findings.json}"
[[ -d "${REPO:-}" ]] || { echo "ERROR: repo not found: $REPO" >&2; exit 2; }

# 0) Ensure the strict repo scanner exists
if [[ ! -x "$HOME/crs_repo_cwe_strict.sh" ]]; then
  echo "ERROR: ~/crs_repo_cwe_strict.sh not found or not executable." >&2
  echo "Please save the strict scanner there and chmod +x it." >&2
  exit 3
fi

# 1) Make sure services are up (compose v2 syntax; adjust path if needed)
echo "==> Starting/ensuring containers..."
docker-compose up -d
echo "==> Waiting for health..."
# wait for webservice to report healthy
for i in {1..30}; do
  if curl -sf http://127.0.0.1:8000/healthz >/dev/null; then
    echo "   webservice OK"
    break
  fi
  sleep 2
done

# 2) Make sure the model is present (idempotent)
MODEL="${MODEL_NAME:-llama3.1:8b-instruct-q4_K_M}"
echo "==> Ensuring model is pulled: $MODEL"
docker exec -i ollama ollama pull "$MODEL" >/dev/null || true

# 3) Optional warm-up (fast no-op)
echo "==> Warm-up generate"
curl -s -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"ok"}],"stream":false,"llm_max_tokens":8}' \
  http://127.0.0.1:8000/v1/crs/run >/dev/null || true

# 4) Run the strict repo scan (THIS is the actual scan step)
echo "==> Launching strict repo scan…"
(
  SHOW_LOGS="${SHOW_LOGS:-1}" \
  MAX_TOTAL_BYTES="${MAX_TOTAL_BYTES:-120000}" \
  CHUNK_BYTES="${CHUNK_BYTES:-7000}" \
  BATCH_FILES="${BATCH_FILES:-10}" \
  LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-700}" \
  TIMEOUT="${TIMEOUT:-900}" \
  INCLUDE_PATHS="${INCLUDE_PATHS:-}" \
  EXCLUDE_PATHS="${EXCLUDE_PATHS:-.git target build dist out node_modules .mvn .github}" \
  "$HOME/crs_repo_cwe_strict.sh" \
    "$REPO" \
    "$FOCUS" \
    "$OUT"
)

echo "==> Done. Findings written to: $OUT"
