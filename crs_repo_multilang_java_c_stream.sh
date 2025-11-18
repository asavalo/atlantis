#!/usr/bin/env bash
# Strict per-file CRS run for Java/C codebases with live logs.
# - No dependence on crs-multilang being present in the container.
# - Posts a strict JSON prompt per file to /v1/crs/run.
#
# Usage:
#   ./crs_repo_strict_java_c.sh <repo_dir> <out.json> [BATCH_SIZE]
# Example:
#   ./crs_repo_strict_java_c.sh ~/accumulo ~/multilang_accumulo_findings.json 50

set -euo pipefail

REPO="${1:-}"
OUT="${2:-$(pwd)/findings.json}"
BATCH_SIZE="${3:-50}"

[[ -n "$REPO" && -d "$REPO" ]] || { echo "Usage: $0 <repo_dir> <out.json> [BATCH_SIZE]"; exit 2; }

# Detect docker compose flavor
if docker compose version >/dev/null 2>&1; then
  DCMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DCMD="docker-compose"
else
  echo "ERROR: neither 'docker compose' nor 'docker-compose' found"; exit 4
fi

: "${ENDPOINT:=http://127.0.0.1:8000/v1/crs/run}"
: "${LLM_MAX_TOKENS:=512}"
: "${LLM_TEMPERATURE:=0}"
: "${MAX_BYTES_PER_FILE:=180000}"      # cap per-file content to avoid context overflow
: "${TIMEOUT:=900}"                    # seconds per request
: "${RETRIES:=2}"                      # retry on HTTP !200 or empty/bad JSON

WORK="$(mktemp -d)"
LOGDIR="$WORK/logs"
JSONL="$WORK/findings.jsonl"
LIST="$WORK/files.txt"
mkdir -p "$LOGDIR"
: > "$JSONL"

echo "WORKDIR: $WORK"
echo "Repo: $REPO"
echo "Output: $OUT"
echo "BATCH_SIZE: $BATCH_SIZE"
echo "Endpoint: $ENDPOINT"

# Start live logs (don’t let pipeline failures abort the script)
set +o pipefail
$DCMD logs -f --tail=0 atlantis-webservice | tee "$LOGDIR/webservice.log" &
PID1=$!
$DCMD logs -f --tail=0 ollama              | tee "$LOGDIR/ollama.log" &
PID2=$!
set -o pipefail
cleanup() { kill "$PID1" "$PID2" 2>/dev/null || true; }
trap cleanup EXIT

# Health check (non-fatal)
BASE="${ENDPOINT%/v1/crs/run}"
echo "==> Health check: $BASE/healthz"
ok=0; for i in $(seq 1 30); do curl -sf "$BASE/healthz" >/dev/null 2>&1 && { ok=1; break; }; sleep 1; done
[[ "$ok" -eq 1 ]] && echo "OK webservice healthy" || echo "WARN: healthz failed; proceeding"

# Build file list (.java .c .h only), skip build/test noise
echo "==> Building file list (.java .c .h only)"
find "$REPO" -type f \
  \( -iname '*.java' -o -iname '*.c' -o -iname '*.h' \) \
  ! -path '*/.git/*' \
  ! -path '*/target/*' \
  ! -path '*/build/*' \
  ! -path '*/out/*' \
  ! -path '*/node_modules/*' \
  ! -path '*/test/resources/*' \
  ! -path '*/testdata/*' \
  -print | LC_ALL=C sort -u > "$LIST"

TOTAL="$(wc -l < "$LIST" | tr -d ' ')"
echo "==> Found $TOTAL files to analyze"
if [[ "$TOTAL" -eq 0 ]]; then echo "[]">$OUT; echo "Nothing to scan."; exit 0; fi

BATCH_NUM=0
SCANNED=0
FOUND=0

# Python helper for payload + salvage
PYHELP="$WORK/make_and_salvage.py"
cat > "$PYHELP" <<'PY'
import sys, json, os, re

mode = sys.argv[1]      # "make" or "salvage"
if mode == "make":
    # args: make <path> <content_file> <max_tokens> <temperature>
    path      = sys.argv[2]
    cfile     = sys.argv[3]
    max_toks  = int(sys.argv[4])
    temp      = float(sys.argv[5])
    content   = open(cfile,'r',encoding='utf-8',errors='ignore').read()

    sysmsg = ("You are a strict vulnerability triage agent. "
              "Return ONLY a JSON array of concrete CWE findings for the given file. "
              "No prose. Fields per item: path, cwe_guess, severity, confidence (0..1), "
              "lines (array of ints), snippet, evidence, reasoning, fix.")

    usr_obj = {
      "task": "vuln-scan",
      "scope": "single-file",
      "target_path": path,
      "allowed_languages": ["java","c"],
      "rules": {
        "no_prose": True,
        "json_only": True,
        "max_items": 10
      }
    }

    payload = {
      "messages": [
        {"role":"system","content": sysmsg},
        {"role":"user","content": json.dumps(usr_obj, ensure_ascii=False)},
        {"role":"user","content": content}
      ],
      "format": "json",
      "stream": False,
      "llm_max_tokens": max_toks,
      "llm_temperature": temp
    }
    print(json.dumps(payload))
    sys.exit(0)

# salvage
raw = open(sys.argv[2],'r',errors='ignore').read()

def try_arr(x):
    try:
        j = json.loads(x)
        if isinstance(j, list): return j
        if isinstance(j, dict) and isinstance(j.get("findings"), list): return j["findings"]
    except: pass
    return None

arr = try_arr(raw)
if arr is None:
    last=None
    for m in re.finditer(r"```json\s*([\s\S]*?)```", raw, re.I):
        last=m.group(1)
    if last:
        arr = try_arr(last)

if arr is None:
    # last top-level bracketed array
    start=None; depth=0; loc=None
    for i,ch in enumerate(raw):
        if ch=='[':
            if depth==0: start=i
            depth+=1
        elif ch==']':
            if depth>0:
                depth-=1
                if depth==0 and start is not None: loc=(start,i+1)
    if loc:
        arr = try_arr(raw[loc[0]:loc[1]])

print(json.dumps(arr if arr is not None else [], ensure_ascii=False))
PY

# Process files
while IFS= read -r F; do
  [[ -f "$F" ]] || continue
  SCANNED=$((SCANNED+1))
  if (( (SCANNED-1) % BATCH_SIZE == 0 )); then
    BATCH_NUM=$((BATCH_NUM+1))
    REMAIN=$(( TOTAL - SCANNED + 1 ))
    THISBATCH=$(( REMAIN < BATCH_SIZE ? REMAIN : BATCH_SIZE ))
    echo
    echo "==== Batch $BATCH_NUM (files: $THISBATCH) ===="
  fi

  echo "-- [$SCANNED/$TOTAL] $F"

  # Number lines and cap bytes to avoid overlong payloads
  TMP_SRC="$(mktemp)"
  nl -ba "$F" | head -c "$MAX_BYTES_PER_FILE" > "$TMP_SRC"

  # Build payload
  PAY="$(mktemp)"
  python3 "$PYHELP" make "$F" "$TMP_SRC" "$LLM_MAX_TOKENS" "$LLM_TEMPERATURE" > "$PAY"

  # Call API with retries, salvage JSON if needed
  BODY="$(mktemp)"; CODE=0; OK=0
  for r in $(seq 0 "$RETRIES"); do
    curl -sS -w "\n%{http_code}\n" --max-time "$TIMEOUT" \
      -H "Content-Type: application/json" \
      -d @"$PAY" "$ENDPOINT" \
      | sed -n '1h;1!H;${;g;s/\n\([0-9][0-9][0-9]\)\n$/\n\1\n/;p;}' \
      > "$BODY"
    CODE="$(tail -n1 "$BODY" | tr -d '\r\n')"
    sed -n '$!p' "$BODY" > "$BODY.data"
    if [[ "$CODE" == "200" ]]; then
      OK=1; break
    fi
    echo "   ↳ HTTP=$CODE (retry $r/$RETRIES)"
    sleep 1
  done
  if [[ "$OK" -ne 1 ]]; then
    echo "   ↳ giving up on $F (HTTP $CODE)"
    continue
  fi

  # Salvage → array
  ARR="$(mktemp)"
  python3 "$PYHELP" salvage "$BODY.data" > "$ARR" || echo "[]">"$ARR"

  # Count + append (each finding as one JSON line)
  NEW="$(jq -r 'length' "$ARR" 2>/dev/null || echo 0)"
  if [[ -n "$NEW" && "$NEW" != "null" && "$NEW" != "0" ]]; then
    # Inject path if missing
    jq -c --arg p "$F" 'map(if has("path") then . else . + {path:$p} end) | .[]' "$ARR" >> "$JSONL"
  fi
  FOUND=$((FOUND + ${NEW:-0}))
  echo "   ↳ findings: ${NEW:-0} (cumulative: $FOUND)"

done < "$LIST"

# Merge lines → pretty array
if [[ -s "$JSONL" ]]; then
  jq -s '
    map(select(type=="object")
        | {path,cwe_guess,severity,confidence,lines,snippet,evidence,reasoning,fix})
    | sort_by(-(.confidence // 0))
  ' "$JSONL" > "$OUT"
else
  echo "[]" > "$OUT"
fi

echo
jq 'length as $n | "TOTAL findings=\($n)"' "$OUT" 2>/dev/null || true
echo "WROTE $OUT"
echo "Logs: $LOGDIR"
