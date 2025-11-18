#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <git_repo_url> <question...>"
  exit 1
fi
REPO_URL="$1"; shift
QUESTION="$*"

# Sparse targets (small but useful for Accumulo)
SPARSE_PATHS=(
  README.md
  core/src/main/java/org/apache/accumulo/core/client/AccumuloClient.java
  core/src/main/java/org/apache/accumulo/core/client/Scanner.java
  core/src/main/java/org/apache/accumulo/core/client/BatchWriter.java
)

# Size caps (tune up/down as needed)
MAX_TOTAL_BYTES=${MAX_TOTAL_BYTES:-120000}   # ~120 KB total
MAX_PER_FILE=${MAX_PER_FILE:-40000}         # ~40 KB/file
CHUNK_BYTES=${CHUNK_BYTES:-10000}           # ~10 KB per message chunk
MAX_CHUNKS=${MAX_CHUNKS:-12}                # don’t send more than this many chunks

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
  BYTES_LEFT=$((MAX_TOTAL_BYTES - TOTAL)); (( BYTES_LEFT <= 0 )) && break
  CAP=$MAX_PER_FILE; (( CAP > BYTES_LEFT )) && CAP=$BYTES_LEFT
  printf "\n===== PATH: %s =====\n" "$p" >> "$CTX"
  head -c "$CAP" "$p" >> "$CTX" || true
  TOTAL=$(wc -c < "$CTX")
done
echo "Context bytes: $TOTAL"

# Split into chunks
CHUNKS_DIR="$WORKDIR/chunks"
mkdir -p "$CHUNKS_DIR"
# split by bytes; names xaa, xab, ...
split -b "$CHUNK_BYTES" -d -a 3 "$CTX" "$CHUNKS_DIR/chunk_"
mapfile -t CHUNK_FILES < <(ls -1 "$CHUNKS_DIR"/chunk_* 2>/dev/null | head -n "$MAX_CHUNKS")
N=${#CHUNK_FILES[@]}
echo "Sending $N chunk(s) of ~${CHUNK_BYTES} bytes each (max $MAX_CHUNKS)."

# Build messages array
TMPMSG="$WORKDIR/messages.jsonl"
: > "$TMPMSG"
# system
jq -cn --arg c "You are a code review/search assistant. Answer ONLY from the provided repository context chunks. If unknown, say so. Always cite file paths you saw inside the chunks." \
   '{role:"system", content:$c}' >> "$TMPMSG"
# chunks
i=1
for f in "${CHUNK_FILES[@]}"; do
  jq -cn --rawfile c "$f" --arg i "$i" --arg n "$N" \
    '{role:"user", content:("Context chunk ("+$i+"/"+$n+"): \n\n"+$c)}' >> "$TMPMSG"
  i=$((i+1))
done
# final task/question
jq -cn --arg q "$QUESTION" '{role:"user", content:("Task: "+$q)}' >> "$TMPMSG"

# Turn JSONL → JSON array
MESSAGES="$(jq -s '.' "$TMPMSG")"

# Compose request
REQ="$(jq -n --argjson messages "$MESSAGES" '{messages:$messages, stream:false}')"

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

jq -r '.output // empty' < "$RESP"
