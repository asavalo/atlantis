#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <git_repo_url> <question...>"
  exit 1
fi
REPO_URL="$1"; shift
QUESTION="$*"

# what to fetch (sparse, tiny test)
SPARSE_PATHS=(
  README.md
  core/src/main/java/org/apache/accumulo/core/client/AccumuloClient.java
)

# context limits (kept small for the test)
MAX_TOTAL_BYTES=${MAX_TOTAL_BYTES:-150000}   # ~150 KB total
MAX_PER_FILE=${MAX_PER_FILE:-100000}         # up to 100 KB/file

WORKDIR="$(mktemp -d)"
REPO_DIR="$WORKDIR/repo"
CTX="$WORKDIR/context.txt"
RESP="$WORKDIR/resp.json"

echo "==> Sparse clone"
git clone --depth 1 --filter=blob:none --no-checkout "$REPO_URL" "$REPO_DIR" >/dev/null
cd "$REPO_DIR"
git sparse-checkout init --cone >/dev/null
git sparse-checkout set "${SPARSE_PATHS[@]}" >/dev/null || true
git checkout >/dev/null

echo "==> Packing context"
: > "$CTX"
TOTAL=0
for p in "${SPARSE_PATHS[@]}"; do
  [[ -f "$p" ]] || continue
  BYTES_LEFT=$((MAX_TOTAL_BYTES - TOTAL))
  (( BYTES_LEFT <= 0 )) && break
  CAP=$MAX_PER_FILE; (( CAP > BYTES_LEFT )) && CAP=$BYTES_LEFT
  echo -e "\n===== PATH: ${p} =====" >> "$CTX"
  head -c "$CAP" "$p" >> "$CTX" || true
  TOTAL=$(wc -c < "$CTX")
done
echo "Context bytes: $TOTAL"

# Compose request using --rawfile (no brittle sed/escaping)
REQ="$(jq -n --rawfile ctx "$CTX" --arg q "$QUESTION" '{
  messages: [
    {role:"system", content:"You are a code review/search assistant. Answer ONLY from the provided repository context. If unknown, say so. Always cite file paths from the context where evidence came from."},
    {role:"user", content: ("Repository context:\n\n" + $ctx + "\n\nTask: " + $q)}
  ],
  stream: false
}')"

echo "==> Calling local CRS"
HTTP_CODE=$(
  curl -sS -w '%{http_code}' -o "$RESP" \
    -H "Content-Type: application/json" \
    -d "$REQ" \
    http://127.0.0.1:8000/v1/crs/run
)

if [[ "$HTTP_CODE" != "200" ]]; then
  echo "CRS returned HTTP $HTTP_CODE"
  echo "---- raw body ----"
  cat "$RESP"
  echo
  exit 1
fi

# Print the model's output (if the JSON has .output)
jq -r '.output // empty' < "$RESP"
