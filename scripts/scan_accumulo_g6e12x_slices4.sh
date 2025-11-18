#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-}"; OUT="${2:-$HOME/multilang_accumulo_findings.json}"
[[ -n "${REPO}" && -d "${REPO}" ]] || { echo "Usage: $0 <repo_dir> <out.json>"; exit 2; }

# ---- Tunables ----
WORKERS=${WORKERS:-4}                 # g6e.12xlarge → 4 GPUs
PORT_OFFSET=${PORT_OFFSET:-0}
MODEL_NAME=${MODEL_NAME:-"llama3.1:8b-instruct-q4_K_M"}

# --- Add these near the top, with the other tunables ---
MODEL_NAME=${MODEL_NAME:-"llama3.1:8b-instruct-q4_K_M"}
OLLAMA_VOL=${OLLAMA_VOL:-"ollama-models"}        # named docker volume for models
OLLAMA_MODELDIR=${OLLAMA_MODELDIR:-"/root/.ollama"}  # default path inside container

# Ensure shared model volume exists
docker volume inspect "${OLLAMA_VOL}" >/dev/null 2>&1 || docker volume create "${OLLAMA_VOL}" >/dev/null


BASE_MAX_BYTES=${MAX_BYTES_PER_FILE:-60000}   # smaller payloads
BASE_MAX_TOKENS=${LLM_MAX_TOKENS:-256}
TEMP=${LLM_TEMPERATURE:-0}
TIMEOUT=${TIMEOUT:-2400}              # longer curl timeout
RETRIES=${RETRIES:-5}
JITTER=${JITTER:-0.15}

NETWORK=${NETWORK:-"atl-net"}
ATLAS_IMG=${ATLAS_IMG:-"asavalo-atlantis-webservice"}

command -v nvidia-smi >/dev/null || { echo "ERROR: nvidia-smi missing"; exit 3; }
docker network inspect "${NETWORK}" >/dev/null 2>&1 || docker network create "${NETWORK}" >/dev/null

start_worker() {
  local i="$1"
  local OPORT=$((11434 + PORT_OFFSET + i))
  local WPORT=$((8000  + PORT_OFFSET + i))

  # Ollama worker with shared model store
  if ! docker ps --format '{{.Names}}' | grep -qx "ollama-$i"; then
    docker run -d --rm \
      --gpus "device=$i" \
      --name "ollama-$i" \
      --network "${NETWORK}" \
      -p "127.0.0.1:${OPORT}:11434" \
      -e OLLAMA_NUM_GPU=1 \
      -e OLLAMA_MODELS="${OLLAMA_MODELDIR}" \
      -v "${OLLAMA_VOL}:${OLLAMA_MODELDIR}" \
      ollama/ollama:latest >/dev/null
  fi

  # Ensure model is present in the shared store (one-time pull is fine; harmless if already present)
  docker exec -i "ollama-$i" ollama list | grep -q "^${MODEL_NAME}\b" || \
    docker exec -i "ollama-$i" ollama pull "${MODEL_NAME}"

  # Atlantis webservice pointing at this worker
  if ! docker ps --format '{{.Names}}' | grep -qx "atl-web-$i"; then
    docker run -d --rm \
      --name "atl-web-$i" \
      --network "${NETWORK}" \
      -p "127.0.0.1:${WPORT}:8000" \
      -e OLLAMA_URL="http://ollama-$i:11434" \
      -e MODEL_NAME="${MODEL_NAME}" \
      -e OLLAMA_READ_TIMEOUT="900" \
      -e OLLAMA_CONNECT_TIMEOUT="45" \
      "${ATLAS_IMG}" >/dev/null
  fi
}

echo "=> Starting ${WORKERS} workers (PORT_OFFSET=${PORT_OFFSET})"
for i in $(seq 0 $((WORKERS-1))); do start_worker "$i"; done

echo "==> Verifying model presence on all workers"
for i in $(seq 0 $((WORKERS-1))); do
  echo -n "  worker[$i] model: "
  docker exec -i "ollama-$i" ollama list | awk '{print $1}' | grep -m1 -E "^${MODEL_NAME//\./\\.}$" || echo "MISSING"
done


echo "==> Health checks"
for i in $(seq 0 $((WORKERS-1))); do
  WPORT=$((8000 + PORT_OFFSET + i))
  for t in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:${WPORT}/healthz" >/dev/null 2>&1; then
      echo "  worker[$i] OK on ${WPORT}"
      break
    fi
    sleep 1
    [[ $t -eq 60 ]] && echo "  worker[$i] WARN: healthz not responding"
  done
done

echo "==> Building file list (.java .c .h)"
LIST="$(mktemp)"
find "${REPO}" -type f \( -iname '*.java' -o -iname '*.c' -o -iname '*.h' \) \
  ! -path '*/.git/*' ! -path '*/target/*' ! -path '*/build/*' ! -path '*/out/*' \
  ! -path '*/node_modules/*' ! -path '*/test/resources/*' ! -path '*/testdata/*' \
  | LC_ALL=C sort -u > "${LIST}"
TOTAL=$(wc -l < "${LIST}" | tr -d ' ')
echo "==> Files to scan: ${TOTAL}"
[[ "${TOTAL}" -gt 0 ]] || { echo "[]">${OUT}; exit 0; }

SPLIT_DIR="$(mktemp -d)"
cp ~/subset.txt "${LIST}"; split -n "l/${WORKERS}" "${LIST}" "${SPLIT_DIR}/part_"

WORKDIR="$(mktemp -d)"
BYFILE_DIR="${WORKDIR}/vuln_by_file"
JSONL_DIR="${WORKDIR}/jsonl"
mkdir -p "${BYFILE_DIR}" "${JSONL_DIR}"
echo "WORKDIR: ${WORKDIR}"
echo "Per-file findings: ${BYFILE_DIR}"

PYHELP="${WORKDIR}/helper.py"
cat > "${PYHELP}" <<'PY'
import sys, json, re
mode = sys.argv[1]

def try_arr(x):
  try:
    j = json.loads(x)
    if isinstance(j, list): return j
    if isinstance(j, dict) and isinstance(j.get("findings"), list): return j["findings"]
  except Exception:
    pass
  return None

if mode == "make":
  path, cfile, max_toks, temp = sys.argv[2], sys.argv[3], int(sys.argv[4]), float(sys.argv[5])
  content = open(cfile,'r',encoding='utf-8',errors='ignore').read()
  sysmsg = ("You are a strict vulnerability triage agent. "
            "Return ONLY a JSON array of concrete CWE findings for the given file. "
            "No prose. Fields per item: path, cwe_guess, severity, confidence (0..1), "
            "lines (array of ints), snippet, evidence, reasoning, fix.")
  usr = {"task":"vuln-scan","scope":"single-file","target_path":path,
         "allowed_languages":["java","c"],
         "rules":{"no_prose":True,"json_only":True,"max_items":10}}
  payload = {"messages":[
      {"role":"system","content":sysmsg},
      {"role":"user","content":json.dumps(usr,ensure_ascii=False)},
      {"role":"user","content":content}],
    "format":"json","stream":False,
    "llm_max_tokens":max_toks,"llm_temperature":temp}
  print(json.dumps(payload,ensure_ascii=False)); sys.exit(0)

# salvage
raw = open(sys.argv[2],'r',errors='ignore').read()
arr = try_arr(raw)
if arr is None:
  for m in re.finditer(r"```json\s*([\s\S]*?)```", raw, re.I):
    arr = try_arr(m.group(1))
    if arr is not None: break
if arr is None:
  start=None; depth=0; loc=None
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

scan_one_payload() {
  # args: worker_idx file_path max_bytes max_tokens [content_override]
  local idx="$1" F="$2" CAP="$3" TOK="$4" COV="${5:-}"
  local ENDPOINT="http://127.0.0.1:$((8000+PORT_OFFSET+idx))/v1/crs/run"

  local SRC PAY BODY CODE OK=0
  if [[ -n "$COV" && -f "$COV" ]]; then
    SRC="$COV"
  else
    SRC="$(mktemp)"; nl -ba "$F" | head -c "$CAP" > "$SRC"
  fi
  PAY="$(mktemp)"; python3 "${PYHELP}" make "$F" "$SRC" "$TOK" "$TEMP" > "$PAY"
  BODY="$(mktemp)"

  for r in $(seq 0 "${RETRIES}"); do
    curl -sS -w "\n%{http_code}\n" --max-time "${TIMEOUT}" \
      -H "Content-Type: application/json" -d @"$PAY" "$ENDPOINT" \
    | sed -n '1h;1!H;${;g;s/\n\([0-9][0-9][0-9]\)\n$/\n\1\n/;p;}' > "$BODY"
    CODE="$(tail -n1 "$BODY" | tr -d '\r\n')"
    sed -n '$!p' "$BODY" > "$BODY.data"
    if [[ "$CODE" == "200" ]]; then OK=1; break; fi
    sleep 1
  done
  echo "$OK" "$BODY"
}

slice_file_n() {
  # args: file n_slices slice_index(1-based) out_path
  local F="$1" N="$2" K="$3" OUT="$4"
  local NL="$(mktemp)"; nl -ba "$F" > "$NL"
  local LINES; LINES=$(wc -l < "$NL"); [[ "$LINES" -eq 0 ]] && { :> "$OUT"; return; }
  local CHUNK=$(( (LINES + N - 1) / N ))
  local START=$(( (K-1)*CHUNK + 1 ))
  local END=$(( K*CHUNK ))
  sed -n "${START},${END}p" "$NL" > "$OUT"
}

run_chunk() {
  local idx="$1" chunk="$2" out_jsonl="$3"
  local scanned=0 found=0 total_chunk; total_chunk=$(wc -l < "$chunk" | tr -d ' ')
  echo "==> Worker[$idx] scanning ${total_chunk} files"

  while IFS= read -r F; do
    [[ -f "$F" ]] || continue
    scanned=$((scanned+1))
    printf "  [w%u %u/%u] %s\n" "$idx" "$scanned" "$total_chunk" "$F"

    # A) base
    read OK BODY <<< "$(scan_one_payload "$idx" "$F" "$BASE_MAX_BYTES" "$BASE_MAX_TOKENS")"
    if [[ "$OK" -ne 1 ]]; then
      echo "    ↳ 500 at base caps → halving payload"
      read OK BODY <<< "$(scan_one_payload "$idx" "$F" "$((BASE_MAX_BYTES/2))" "$((BASE_MAX_TOKENS-64))")"
    fi

    # B) halves
    if [[ "$OK" -ne 1 ]]; then
      echo "    ↳ 500 again → 2 slices"
      local SLICE; SLICE="$(mktemp)"
      for k in 1 2; do
        slice_file_n "$F" 2 "$k" "$SLICE"
        read OK BODY <<< "$(scan_one_payload "$idx" "$F" "$((BASE_MAX_BYTES/2))" "$((BASE_MAX_TOKENS-64))" "$SLICE")"
        [[ "$OK" -eq 1 ]] && break
      done
    fi

    # C) quarters
    if [[ "$OK" -ne 1 ]]; then
      echo "    ↳ still 500 → 4 slices"
      local SLICE; SLICE="$(mktemp)"
      for k in 1 2 3 4; do
        slice_file_n "$F" 4 "$k" "$SLICE"
        read OK BODY <<< "$(scan_one_payload "$idx" "$F" "$((BASE_MAX_BYTES/4))" "$((BASE_MAX_TOKENS-96))" "$SLICE")"
        [[ "$OK" -eq 1 ]] && break
      done
    fi

    if [[ "$OK" -ne 1 ]]; then
      mkdir -p "${WORKDIR}/errors_w${idx}"
      head -c 2048 "$BODY.data" > "${WORKDIR}/errors_w${idx}/$(basename "$F").err"
      echo "    ↳ giving up on: $F"
      continue
    fi

    # Salvage → array
    ARR="$(mktemp)"; python3 "${PYHELP}" salvage "$BODY.data" > "$ARR" || echo "[]">"$ARR"
    REL="${F#${REPO}/}"; [[ "$REL" == "$F" ]] && REL="$F"
    SAFE="$(printf '%s' "$REL" | sed 's#[/ ]#__#g')"
    PFF="${BYFILE_DIR}/${SAFE}.json"

    NEW="$(jq -r 'length' "$ARR" 2>/dev/null || echo 0)"
    if [[ -n "$NEW" && "$NEW" != "null" && "$NEW" != "0" ]]; then
      jq --arg p "$F" 'map(if has("path") then . else . + {path:$p} end)' "$ARR" > "$PFF"
      jq -c '.[]' "$PFF" >> "$out_jsonl"
    else
      echo "[]" > "$PFF"
    fi
    found=$((found + ${NEW:-0}))
    printf "    ↳ findings: %s (w%u total: %u)  → %s\n" "${NEW:-0}" "$idx" "$found" "$PFF"
    sleep "$JITTER"
  done < "$chunk"

  echo "==> Worker[$idx] done. Files: $scanned  Findings: $found"
}

# Launch workers
pids=(); i=0
for chunk in "${SPLIT_DIR}"/part_*; do
  out_jsonl="${JSONL_DIR}/w_${i}.jsonl"; : > "$out_jsonl"
  run_chunk "$i" "$chunk" "$out_jsonl" &
  pids+=($!); i=$((i+1))
done
for p in "${pids[@]}"; do wait "$p"; done

# Merge
if ls "${JSONL_DIR}"/w_*.jsonl >/dev/null 2>&1; then
  cat "${JSONL_DIR}"/w_*.jsonl | jq -s '
    map(select(type=="object")
      | {path,cwe_guess,severity,confidence,lines,snippet,evidence,reasoning,fix})
    | sort_by(-(.confidence // 0))
  ' > "${OUT}"
else
  echo "[]" > "${OUT}"
fi

jq 'length as $n | "TOTAL findings=\($n)"' "${OUT}" 2>/dev/null || true
echo "WROTE ${OUT}"
echo "Per-file findings: ${BYFILE_DIR}"
echo "Errors (if any): ${WORKDIR}/errors_w*/"
echo
echo "Stop workers:"
echo "  docker rm -f $(printf 'ollama-%s ' $(seq 0 $((WORKERS-1)))) >/dev/null 2>&1 || true"
echo "  docker rm -f $(printf 'atl-web-%s ' $(seq 0 $((WORKERS-1)))) >/dev/null 2>&1 || true"
