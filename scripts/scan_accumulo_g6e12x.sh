#!/usr/bin/env bash
# Parallel CRS scanner for Accumulo on g6e.12xlarge (4× L40S).
# - 4 workers (one per GPU), strict JSON prompts, retries, error capture.
# - Per-file findings saved under WORKDIR/vuln_by_file/<safe-name>.json
# - Final merged pretty JSON written to <out.json>
#
# Usage:
#   ./scan_accumulo_g6e12x.sh <repo_dir> <out.json>
#
# Env overrides (optional):
#   WORKERS=4 PORT_OFFSET=0 MODEL_NAME="llama3.1:8b-instruct-q4_K_M"
#   MAX_BYTES_PER_FILE=120000 LLM_MAX_TOKENS=384 LLM_TEMPERATURE=0
#   TIMEOUT=1200 RETRIES=3 NETWORK="atl-net" ATLAS_IMG="asavalo-atlantis-webservice"

set -euo pipefail

REPO="${1:-}"
OUT="${2:-$HOME/multilang_accumulo_findings.json}"
[[ -n "${REPO}" && -d "${REPO}" ]] || { echo "Usage: $0 <repo_dir> <out.json>"; exit 2; }

# --- Tunables ---
WORKERS=${WORKERS:-4}                            # g6e.12xlarge → 4 GPUs
PORT_OFFSET=${PORT_OFFSET:-0}                    # shift ports if something already uses 11434/8000
MODEL_NAME=${MODEL_NAME:-"llama3.1:8b-instruct-q4_K_M"}

MAX_BYTES_PER_FILE=${MAX_BYTES_PER_FILE:-120000} # cap per-file input (numbered lines)
LLM_MAX_TOKENS=${LLM_MAX_TOKENS:-384}
LLM_TEMPERATURE=${LLM_TEMPERATURE:-0}
TIMEOUT=${TIMEOUT:-1200}                         # per-request seconds
RETRIES=${RETRIES:-3}
JITTER=${JITTER:-0.1}                            # tiny sleep to smooth bursts

NETWORK=${NETWORK:-"atl-net"}
ATLAS_IMG=${ATLAS_IMG:-"asavalo-atlantis-webservice"}  # change if your tag differs

# --- Sanity: NVIDIA present ---
command -v nvidia-smi >/dev/null || { echo "ERROR: nvidia-smi not found"; exit 3; }

# --- Network ---
docker network inspect "${NETWORK}" >/dev/null 2>&1 || docker network create "${NETWORK}" >/dev/null

# --- Helper: start worker i (ollama + webservice) on GPU i ---
start_worker() {
  local i="$1"
  local OPORT=$((11434 + PORT_OFFSET + i))
  local WPORT=$((8000  + PORT_OFFSET + i))

  # Ollama pinned to GPU i
  if ! docker ps --format '{{.Names}}' | grep -qx "ollama-$i"; then
    docker run -d --rm --gpus "device=$i" \
      --name "ollama-$i" \
      --network "${NETWORK}" \
      -p "127.0.0.1:${OPORT}:11434" \
      -e OLLAMA_NUM_GPU=1 \
      ollama/ollama:latest >/dev/null
  fi

  # Webservice pointing to its sibling Ollama
  if ! docker ps --format '{{.Names}}' | grep -qx "atl-web-$i"; then
    docker run -d --rm \
      --name "atl-web-$i" \
      --network "${NETWORK}" \
      -p "127.0.0.1:${WPORT}:8000" \
      -e OLLAMA_URL="http://ollama-$i:11434" \
      -e MODEL_NAME="${MODEL_NAME}" \
      -e OLLAMA_READ_TIMEOUT="600" \
      -e OLLAMA_CONNECT_TIMEOUT="30" \
      "${ATLAS_IMG}" >/dev/null
  fi
}

echo "==> Starting ${WORKERS} workers… (PORT_OFFSET=${PORT_OFFSET})"
for i in $(seq 0 $((WORKERS-1))); do start_worker "$i"; done

# --- Health checks ---
echo "==> Health checks"
for i in $(seq 0 $((WORKERS-1))); do
  WPORT=$((8000 + PORT_OFFSET + i))
  for t in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:${WPORT}/healthz" >/dev/null 2>&1; then
      echo "  worker[$i] OK (port ${WPORT})"
      break
    fi
    sleep 1
    [[ $t -eq 60 ]] && echo "  worker[$i] WARN: healthz not responding"
  done
done

# --- Build file list (.java/.c/.h only), skip build/test noise ---
echo "==> Building file list (.java .c .h)"
LIST="$(mktemp)"
find "${REPO}" -type f \
  \( -iname '*.java' -o -iname '*.c' -o -iname '*.h' \) \
  ! -path '*/.git/*' \
  ! -path '*/target/*' \
  ! -path '*/build/*' \
  ! -path '*/out/*' \
  ! -path '*/node_modules/*' \
  ! -path '*/test/resources/*' \
  ! -path '*/testdata/*' \
  -print | LC_ALL=C sort -u > "${LIST}"

TOTAL=$(wc -l < "${LIST}" | tr -d ' ')
echo "==> Files to scan: ${TOTAL}"
[[ "${TOTAL}" -gt 0 ]] || { echo "[]">${OUT}; echo "No files."; exit 0; }

# --- Split into N chunks ---
SPLIT_DIR="$(mktemp -d)"
split -n "l/${WORKERS}" "${LIST}" "${SPLIT_DIR}/part_"

# --- Work dirs ---
WORK="$(mktemp -d)"
BYFILE_DIR="${WORK}/vuln_by_file"
JSONL_DIR="${WORK}/jsonl"
mkdir -p "${BYFILE_DIR}" "${JSONL_DIR}"
echo "WORKDIR: ${WORK}"
echo "Per-file findings: ${BYFILE_DIR}"

# --- Python helper: strict payload + JSON salvage ---
PYHELP="${WORK}/make_and_salvage.py"
cat > "${PYHELP}" <<'PY'
import sys, json, re
mode = sys.argv[1]

def try_arr(x):
  try:
    j = json.loads(x)
    if isinstance(j, list): return j
    if isinstance(j, dict) and isinstance(j.get("findings"), list): return j["findings"]
  except: pass
  return None

if mode == "make":
  # make <path> <content_file> <max_tokens> <temperature>
  path, cfile, max_toks, temp = sys.argv[2], sys.argv[3], int(sys.argv[4]), float(sys.argv[5])
  content = open(cfile,'r',encoding='utf-8',errors='ignore').read()
  sysmsg = ("You are a strict vulnerability triage agent. "
            "Return ONLY a JSON array of concrete CWE findings for the given file. "
            "No prose. Fields per item: path, cwe_guess, severity, confidence (0..1), "
            "lines (array of ints), snippet, evidence, reasoning, fix.")
  usr = {
    "task":"vuln-scan","scope":"single-file","target_path":path,
    "allowed_languages":["java","c"],
    "rules":{"no_prose":True,"json_only":True,"max_items":10}
  }
  payload = {
    "messages":[
      {"role":"system","content":sysmsg},
      {"role":"user","content":json.dumps(usr,ensure_ascii=False)},
      {"role":"user","content":content}
    ],
    "format":"json","stream":False,
    "llm_max_tokens":max_toks,"llm_temperature":temp
  }
  print(json.dumps(payload,ensure_ascii=False)); sys.exit(0)

# salvage <raw_file>
raw = open(sys.argv[2],'r',errors='ignore').read()
arr = try_arr(raw)
if arr is None:
  last=None
  for m in re.finditer(r"```json\s*([\s\S]*?)```", raw, re.I): last=m.group(1)
  if last: arr = try_arr(last)
if arr is None:
  start=None;depth=0;loc=None
  for i,ch in enumerate(raw):
    if ch=='[':
      if depth==0: start=i
      depth+=1
    elif ch==']':
      if depth>0:
        depth-=1
        if depth==0 and start is not None: loc=(start,i+1)
  if loc: arr = try_arr(raw[loc[0]:loc[1]])
print(json.dumps(arr if arr is not None else [], ensure_ascii=False))
PY

# --- Worker function ---
run_chunk() {
  local idx="$1" chunk="$2" out_jsonl="$3"
  local OPORT=$((11434 + PORT_OFFSET + idx))
  local WPORT=$((8000  + PORT_OFFSET + idx))
  local ENDPOINT="http://127.0.0.1:${WPORT}/v1/crs/run"

  local scanned=0 found=0 total_chunk
  total_chunk=$(wc -l < "$chunk" | tr -d ' ')
  echo "==> Worker[$idx] scanning ${total_chunk} files (web:${WPORT} / ollama:${OPORT})"

  while IFS= read -r F; do
    [[ -f "$F" ]] || continue
    scanned=$((scanned+1))
    printf "  [w%u %u/%u] %s\n" "$idx" "$scanned" "$total_chunk" "$F"

    # Number lines & cap bytes
    TMP_SRC="$(mktemp)"
    nl -ba "$F" | head -c "${MAX_BYTES_PER_FILE}" > "$TMP_SRC"

    # Build strict payload
    PAY="$(mktemp)"
    python3 "${PYHELP}" make "$F" "$TMP_SRC" "${LLM_MAX_TOKENS}" "${LLM_TEMPERATURE}" > "$PAY"

    # Call API with retries; capture body + code
    BODY="$(mktemp)"; CODE=0; OK=0
    for r in $(seq 0 "${RETRIES}"); do
      curl -sS -w "\n%{http_code}\n" --max-time "${TIMEOUT}" \
        -H "Content-Type: application/json" \
        -d @"$PAY" "${ENDPOINT}" \
      | sed -n '1h;1!H;${;g;s/\n\([0-9][0-9][0-9]\)\n$/\n\1\n/;p;}' > "$BODY"
      CODE="$(tail -n1 "$BODY" | tr -d '\r\n')"
      sed -n '$!p' "$BODY" > "$BODY.data"
      if [[ "$CODE" == "200" ]]; then OK=1; break; fi
      echo "    ↳ HTTP=$CODE (retry $r/${RETRIES})"
      # Save first 2KB of error body for debugging
      mkdir -p "${WORK}/errors_w${idx}"
      head -c 2048 "$BODY.data" > "${WORK}/errors_w${idx}/$(basename "$F").err"
      sleep 1
    done
    if [[ "$OK" -ne 1 ]]; then
      echo "    ↳ giving up on $F (HTTP $CODE)"
      continue
    fi

    # Salvage JSON → array
    ARR="$(mktemp)"
    python3 "${PYHELP}" salvage "$BODY.data" > "$ARR" || echo "[]">"$ARR"
    NEW="$(jq -r 'length' "$ARR" 2>/dev/null || echo 0)"

    # Attach path and write per-file findings
    # Safe filename under vuln_by_file: relative path with slashes/spaces replaced
    REL="${F#${REPO}/}"; [[ "$REL" == "$F" ]] && REL="$F"
    SAFE="$(printf '%s' "$REL" | sed 's#[/ ]#__#g')"
    PFF="${BYFILE_DIR}/${SAFE}.json"

    if [[ -n "$NEW" && "$NEW" != "null" && "$NEW" != "0" ]]; then
      # Enforce path field; write array to per-file JSON and append items to JSONL
      jq --arg p "$F" 'map(if has("path") then . else . + {path:$p} end)' "$ARR" > "$PFF"
      jq -c '.[]' "$PFF" >> "$out_jsonl"
    else
      # Ensure per-file JSON exists (empty array) for traceability
      echo "[]" > "$PFF"
    fi

    found=$((found + ${NEW:-0}))
    printf "    ↳ findings: %s (w%u total: %u)  → %s\n" "${NEW:-0}" "$idx" "$found" "$PFF"

    # tiny jitter to avoid thundering herd
    sleep "${JITTER}"
  done < "$chunk"

  echo "==> Worker[$idx] done. Files: $scanned  Findings: $found"
}

# --- Launch workers on their chunks ---
pids=(); i=0
for chunk in "${SPLIT_DIR}"/part_*; do
  out_jsonl="${JSONL_DIR}/w_${i}.jsonl"
  : > "$out_jsonl"
  run_chunk "$i" "$chunk" "$out_jsonl" &
  pids+=($!)
  i=$((i+1))
done

for p in "${pids[@]}"; do wait "$p"; done

# --- Merge all worker JSONL → final pretty array ---
if ls "${JSONL_DIR}"/w_*.jsonl >/dev/null 2>&1; then
  cat "${JSONL_DIR}"/w_*.jsonl | jq -s '
    map(select(type=="object")
        | {path,cwe_guess,severity,confidence,lines,snippet,evidence,reasoning,fix})
    | sort_by(-(.confidence // 0))
  ' > "${OUT}"
else
  echo "[]" > "${OUT}"
fi

echo
jq 'length as $n | "TOTAL findings=\($n)"' "${OUT}" 2>/dev/null || true
echo "WROTE ${OUT}"
echo "Per-file findings directory: ${BYFILE_DIR}"
echo "Errors (if any): ${WORK}/errors_w*/"
echo
echo "Stop workers later with:"
echo "  docker rm -f $(printf 'ollama-%s ' $(seq 0 $((WORKERS-1)))) >/dev/null 2>&1 || true"
echo "  docker rm -f $(printf 'atl-web-%s ' $(seq 0 $((WORKERS-1)))) >/dev/null 2>&1 || true"
