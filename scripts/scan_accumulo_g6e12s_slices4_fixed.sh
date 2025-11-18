cat > ~/scan_accumulo_g6e12x_slices4_fixed.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-}"; OUT="${2:-$HOME/multilang_accumulo_findings.json}"
[[ -n "${REPO}" && -d "${REPO}" ]] || { echo "Usage: $0 <repo_dir> <out.json>"; exit 2; }

# ---- Tunables ----
WORKERS=${WORKERS:-4}                 # g6e.12xlarge → 4 GPUs
PORT_OFFSET=${PORT_OFFSET:-0}
MODEL_NAME=${MODEL_NAME:-"llama3.1:8b-instruct-q4_K_M"}

BASE_MAX_BYTES=${MAX_BYTES_PER_FILE:-60000}   # conservative payloads
BASE_MAX_TOKENS=${LLM_MAX_TOKENS:-256}
TEMP=${LLM_TEMPERATURE:-0}
TIMEOUT=${TIMEOUT:-2400}
RETRIES=${RETRIES:-5}
JITTER=${JITTER:-0.15}

NETWORK=${NETWORK:-"atl-net"}
ATLAS_IMG=${ATLAS_IMG:-"asavalo-atlantis-webservice"}

# Shared model store so every worker sees the model
OLLAMA_VOL=${OLLAMA_VOL:-"ollama-models"}
OLLAMA_MODELDIR=${OLLAMA_MODELDIR:-"/root/.ollama"}

command -v nvidia-smi >/dev/null || { echo "ERROR: nvidia-smi missing"; exit 3; }
docker network inspect "${NETWORK}" >/dev/null 2>&1 || docker network create "${NETWORK}" >/dev/null
docker volume inspect "${OLLAMA_VOL}" >/dev/null 2>&1 || docker volume create "${OLLAMA_VOL}" >/dev/null

wait_http_ok() {
  # wait_http_ok <url> <seconds> [name-for-logs] [container-name]
  local url="$1" secs="$2" name="${3:-}"; local c="${4:-}"
  for t in $(seq 1 "$secs"); do
    if curl -sf "$url" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "WARN: $name not responding after ${secs}s → dumping logs"
  if [[ -n "$c" ]]; then docker logs --tail=200 "$c" || true; fi
  return 1
}

start_ollama() {
  local i="$1"
  local OPORT=$((11434 + PORT_OFFSET + i))
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
  # Wait for /api/tags
  wait_http_ok "http://127.0.0.1:${OPORT}/api/tags" 120 "ollama-$i" "ollama-$i" || true
  # Ensure model is present
  if ! docker exec -i "ollama-$i" ollama list | awk '{print $1}' | grep -q -E "^${MODEL_NAME//./\\.}$"; then
    echo "==> Pulling model into ollama-$i: ${MODEL_NAME}"
    docker exec -i "ollama-$i" ollama pull "${MODEL_NAME}"
  fi
}

start_web() {
  local i="$1"
  local WPORT=$((8000 + PORT_OFFSET + i))
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
  # Wait for /healthz with logs on failure
  wait_http_ok "http://127.0.0.1:${WPORT}/healthz" 120 "atl-web-$i" "atl-web-$i" || {
    echo "ERROR: atl-web-$i failed healthz"
    exit 4
  }
}

echo "=> Starting ${WORKERS} workers (PORT_OFFSET=${PORT_OFFSET})"
for i in $(seq 0 $((WORKERS-1))); do start_ollama "$i"; done
for i in $(seq 0 $((WORKERS-1))); do start_web "$i"; done

echo "==> Verifying model presence on all workers"
for i in $(seq 0 $((WORKERS-1))); do
  echo -n "  worker[$i] model: "
  docker exec -i "ollama-$i" ollama list | awk '{print $1}' | grep -m1 -E "^${MODEL_NAME//\./\\.}$" || echo "MISSING"
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
split -n "l/${WORKERS}" "${LIST}" "${SPLIT_DIR}/part_"

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

# Merge JSON, ignoring errors completely
#if ls "${JSONL_DIR}"/w_*.jsonl >/dev/null 2>&1; then
#  cat "${JSONL_DIR}"/w_*.jsonl 2>/dev/null \
#  | jq -s 'map(try (fromjson? // .) catch .) | flatten | unique' 2>/dev/null \
#    > "${OUT}" || echo "[]" > "${OUT}"
#else
#  echo "[]" > "${OUT}"
#fi

#jq 'length as $n | "TOTAL findings=\($n)"' "${OUT}" 2>/dev/null || true


echo "[]" > "${OUT}"

# Set a default empty array for the output
echo "[]" > "${OUT}"

# Check if any files matching the pattern exist
if ls "${JSONL_DIR}"/w_*.jsonl >/dev/null 2>&1; then
  
  # This pipeline keeps all records by wrapping non-arrays:
  # 1. 'cat' streams all file contents.
  # 2. 'jq -R 'try fromjson catch .''
  #    - Tries to parse JSON.
  #    - If it fails, it 'catches' the raw line ('.') and passes it as a JSON string.
  # 3. 'jq 'if type == "array" then . else [.] end''
  #    - If the item is an array (like '[{"error": "foo"}]'), pass it.
  #    - If it's not (like '123' or '"bad line"'), wrap it in an array.
  # 4. 'jq -s 'flatten | unique''
  #    - Slurps the stream of arrays into one big array.
  #    - Flattens it and finds unique items.
  cat "${JSONL_DIR}"/w_*.jsonl 2>/dev/null \
    | jq -R 'try fromjson catch .' \
    | jq 'if type == "array" then . else [.] end' \
    | jq -s 'flatten | unique' > "${OUT}" || echo "[]" > "${OUT}"

  # Handle case where no lines were found at all
  if [ ! -s "${OUT}" ] || [ "$(head -n1 "${OUT}")" = "null" ]; then
    echo "[]" > "${OUT}"
  fi

fi

# This counting step is now safe
jq 'length as $n | "TOTAL findings=\($n)"' "${OUT}" 2>/dev/null || \
  echo "TOTAL findings=0 (Error reading ${OUT})"

#echo "WROTE ${OUT}"
#echo "Per-file findings: ${BYFILE_DIR}"


echo "WROTE ${OUT}"
echo "Per-file findings: ${BYFILE_DIR}"
echo "Errors (if any): ${WORKDIR}/errors_w*/"
echo
echo "Stop workers:"
echo "  docker rm -f $(printf 'ollama-%s ' $(seq 0 $((WORKERS-1)))) >/dev/null 2>&1 || true"
echo "  docker rm -f $(printf 'atl-web-%s ' $(seq 0 $((WORKERS-1)))) >/dev/null 2>&1 || true"
SH

chmod +x ~/scan_accumulo_g6e12x_slices4_fixed.sh
