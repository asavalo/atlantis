#!/usr/bin/env bash
set -Eeuo pipefail

# -------- config ----------
API_URL="${API_URL:-http://127.0.0.1:8000/v1/crs/run}"
LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-1024}"     # give more room for full objects
LLM_TEMPERATURE="${LLM_TEMPERATURE:-0}"
MAX_BYTES_PER_FILE="${MAX_BYTES_PER_FILE:-90000}"
MIN_BYTES_PER_FILE="${MIN_BYTES_PER_FILE:-8000}"
RETRIES="${RETRIES:-2}"
SLEEP_BETWEEN="${SLEEP_BETWEEN:-0.5}"
REPAIR_ON_BAD="${REPAIR_ON_BAD:-1}"          # 1 = attempt one repair pass if invalid
WORKDIR="${WORKDIR_OVERRIDE:-"$(mktemp -d)"}"
BYFILE_DIR="$WORKDIR/vuln_by_file"
LOGDIR="$WORKDIR/logs"
# --------------------------

usage() {
  cat <<'USAGE'
Usage:
  crs_drilldown_from_list_min.sh OUTPUT_JSONL --from-file PATHS.txt

  PATHS.txt must contain absolute file paths (one per line).
  Artifacts are under $WORKDIR_OVERRIDE/vuln_by_file (or a temp dir printed at start).
USAGE
}

if (( $# < 2 )) || [[ "${2:-}" != "--from-file" ]]; then
  usage; exit 1
fi

OUT_JSONL="$(realpath -m "$1")"
LIST_FILE="$(realpath -m "$3")"

mkdir -p "$BYFILE_DIR" "$LOGDIR"
touch "${BYFILE_DIR}/.alive" || { echo "ERROR: cannot write to $BYFILE_DIR"; exit 1; }

# Health check
if ! curl -sf "${API_URL%/v1/crs/run}/healthz" >/dev/null; then
  echo "ERROR: webservice not healthy at ${API_URL%/v1/crs/run}/healthz" >&2
  exit 1
fi

echo "WORKDIR: $WORKDIR"
echo "Per-file findings: $BYFILE_DIR"
echo "Output JSONL: $OUT_JSONL"

# robust safe filename: base64 of absolute path
make_safe_name() { printf '%s' "$1" | base64 | tr '/+\n' '__-'; }

build_payload() {  # $1=file $2=body $3=dest_payload.json
  python3 - "$1" "$2" "$3" "$LLM_MAX_TOKENS" "$LLM_TEMPERATURE" <<'PY'
import json, sys, os
path, body_path, dest, max_tokens, temp = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), float(sys.argv[5])
try:
    content = open(body_path,'r',encoding='utf-8',errors='ignore').read()
except Exception:
    content = ""

def guess_lang(p):
    p=p.lower()
    if p.endswith('.java'): return 'java'
    if p.endswith('.c') or p.endswith('.h'): return 'c'
    return 'plain'

# Stronger system prompt + inline JSON schema (as text constraints)
sysmsg = (
  "You are a strict vulnerability triage agent for a SINGLE source file.\n"
  "Output REQUIREMENT: Return ONLY a JSON array of objects, no prose, no code fences.\n"
  "Each object MUST contain ALL of these keys:\n"
  "  path (string), cwe_guess (string like 'CWE-79'), severity ('Low'|'Medium'|'High'),\n"
  "  confidence (number 0..1), lines (array[int]), snippet (string), evidence (string),\n"
  "  reasoning (string), fix (string).\n"
  "Every value must be derived from the file content. If uncertain, return [].\n"
  "Do NOT return arrays of numbers or partial fields."
)

payload = {
  "mode": "multilang",
  "format": "json",
  "stream": False,
  "llm_max_tokens": max_tokens,
  "llm_temperature": temp,
  "messages": [
    {"role":"system","content":sysmsg},
    {"role":"user","content":json.dumps({
      "task":"vuln-scan","scope":"single-file","target_path":path,
      "language":guess_lang(path),
      "allowed_languages":["java","c"],
      "rules":{"json_only":True,"no_prose":True,"require_all_fields":True,"max_items":20}
    }, ensure_ascii=False)},
    {"role":"user","content":content}
  ]
}
with open(dest,'w',encoding='utf-8') as f:
    json.dump(payload,f,ensure_ascii=False)
PY
}

build_repair_payload() {  # $1=file $2=raw_response $3=dest_payload.json $4=body_path
  python3 - "$1" "$2" "$3" "$4" "$LLM_MAX_TOKENS" <<'PY'
import json, sys, os
path, raw_path, dest, body_path, max_tokens = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])

raw = open(raw_path,'r',encoding='utf-8',errors='ignore').read()
try:
    content = open(body_path,'r',encoding='utf-8',errors='ignore').read()
except Exception:
    content = ""

sysmsg = (
  "You are converting an INVALID response into the REQUIRED JSON array of vulnerability objects.\n"
  "Output REQUIREMENT: Return ONLY a JSON array of objects, no prose, no code fences.\n"
  "Each object MUST contain ALL keys: path, cwe_guess, severity, confidence, lines, snippet, evidence, reasoning, fix.\n"
  "Values MUST be derived from the provided file content. If insufficient evidence, return []."
)

payload = {
  "mode": "multilang",
  "format": "json",
  "stream": False,
  "llm_max_tokens": max_tokens,
  "llm_temperature": 0,
  "messages": [
    {"role":"system","content":sysmsg},
    {"role":"user","content":"File path: "+path},
    {"role":"user","content":"File content follows:\n"+content},
    {"role":"user","content":"Previous (invalid) model output — convert to the strict JSON array described above:\n"+raw}
  ]
}
with open(dest,'w',encoding='utf-8') as f:
    json.dump(payload,f,ensure_ascii=False)
PY
}

salvage_array() {  # $1=raw.txt  -> prints array OR "[]"
  python3 - "$1" <<'PY'
import sys, json, re
raw = open(sys.argv[1],'r',encoding='utf-8',errors='ignore').read().strip()

def j(s):
    try: return json.loads(s)
    except: return None

# 1) direct JSON
obj = j(raw)
if isinstance(obj, list): print(json.dumps(obj, ensure_ascii=False)); raise SystemExit
# 2) fenced
m = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", raw, re.S|re.I)
if m:
    arr = j(m.group(1))
    if isinstance(arr, list):
        print(json.dumps(arr, ensure_ascii=False)); raise SystemExit
# 3) first bracketed array
m = re.search(r"\[.*\]", raw, re.S)
if m:
    arr = j(m.group(0))
    if isinstance(arr, list):
        print(json.dumps(arr, ensure_ascii=False)); raise SystemExit
# 4) object with findings
obj = j(raw)
if isinstance(obj, dict) and isinstance(obj.get("findings"), list):
    print(json.dumps(obj["findings"], ensure_ascii=False)); raise SystemExit

print("[]")
PY
}

validate_and_write() {  # $1=arr.json $2=pff $3=OUT_JSONL
  python3 - "$@" <<'PY'
import sys, json

arr_path, pff, out_jsonl = sys.argv[1], sys.argv[2], sys.argv[3]
try:
  data = json.load(open(arr_path,'r'))
except Exception:
  data = []

# keep only proper objects with required keys and types
required = {"path","cwe_guess","severity","confidence","lines","snippet","evidence","reasoning","fix"}
clean = []
for o in data if isinstance(data,list) else []:
  if not isinstance(o, dict): continue
  if not required.issubset(o.keys()): continue
  if not isinstance(o["path"], str): continue
  if not isinstance(o["cwe_guess"], str): continue
  if not isinstance(o["severity"], str): continue
  if not isinstance(o["confidence"], (int,float)): continue
  if not isinstance(o["lines"], list) or not all(isinstance(x,int) for x in o["lines"]): continue
  if not all(isinstance(o[k], str) for k in ("snippet","evidence","reasoning","fix")): continue
  clean.append(o)

with open(pff,'w',encoding='utf-8') as f:
  json.dump(clean, f, ensure_ascii=False)

with open(out_jsonl,'a',encoding='utf-8') as g:
  for o in clean: g.write(json.dumps(o, ensure_ascii=False)+"\n")

print(len(clean))
PY
}

process_file() {  # $1=idx $2=total $3=abs_path
  local idx="$1" total="$2" f="$3"
  local cap="$MAX_BYTES_PER_FILE"
  local tmp; tmp="$(mktemp -d "$WORKDIR/one.XXXX")"
  local safe pff raw httpcode payload arr jsonl repair_payload raw2 arr2

  safe="$(make_safe_name "$f")"
  pff="$BYFILE_DIR/${safe}.json"
  raw="$BYFILE_DIR/${safe}.raw.txt"
  httpcode="$BYFILE_DIR/${safe}.httpcode"
  payload="$BYFILE_DIR/${safe}.payload.json"
  arr="$tmp/arr.json"
  repair_payload="$BYFILE_DIR/${safe}.repair.payload.json"
  raw2="$BYFILE_DIR/${safe}.repair.raw.txt"
  arr2="$tmp/arr2.json"

  echo "[$idx/$total] $f"
  : > "$httpcode" || { echo "   ↳ ERROR: cannot write $httpcode"; return 1; }

  local attempt=0
  while :; do
    head -c "$cap" "$f" > "$tmp/body" 2>/dev/null || : > "$tmp/body"
    build_payload "$f" "$tmp/body" "$payload"

    local code
    code="$(curl -sS -w '%{http_code}' -o "$tmp/resp.data" \
      -H 'Content-Type: application/json' --max-time 300 \
      -X POST "$API_URL" --data-binary @"$payload" || echo "000")"

    echo -n "$code" > "$httpcode" || true
    cp "$tmp/resp.data" "$raw" 2>/dev/null || :

    if [[ "$code" == "200" ]]; then
      salvage_array "$raw" > "$arr" || echo "[]" > "$arr"
      local n; n="$(validate_and_write "$arr" "$pff" "$OUT_JSONL" | tail -n1 || echo 0)"
      if [[ "$n" == "0" && "$REPAIR_ON_BAD" == "1" ]]; then
        echo "   ↳ invalid or empty objects → running repair pass"
        build_repair_payload "$f" "$raw" "$repair_payload" "$tmp/body"

        local code2
        code2="$(curl -sS -w '%{http_code}' -o "$raw2" \
          -H 'Content-Type: application/json' --max-time 300 \
          -X POST "$API_URL" --data-binary @"$repair_payload" || echo "000")"
        salvage_array "$raw2" > "$arr2" || echo "[]" > "$arr2"
        n="$(validate_and_write "$arr2" "$pff" "$OUT_JSONL" | tail -n1 || echo 0)"
      fi
      echo "   ↳ findings: $n"
      break
    fi

    if [[ "$code" =~ ^(500|502|504)$ ]]; then
      if (( attempt < RETRIES )); then
        attempt=$((attempt+1))
        cap=$(( cap / 2 ))
        if (( cap < MIN_BYTES_PER_FILE )); then
          echo "   ↳ giving up: payload too small (${cap}B)"
          break
        fi
        echo "   ↳ HTTP=${code} → reducing payload to ${cap}B and retrying (${attempt}/${RETRIES})"
        continue
      else
        echo "   ↳ giving up (HTTP ${code})"
        break
      fi
    else
      echo "   ↳ HTTP ${code} (no retry policy)"
      break
    fi
  done

  rm -rf "$tmp"
  sleep "$SLEEP_BETWEEN"
}

# ------- read list & run ----------
mapfile -t FILES < <(grep -v '^\s*$' "$LIST_FILE" | sed 's/\r$//' | while IFS= read -r p; do realpath -m "$p"; done)
TOTAL="${#FILES[@]}"

echo "Files to process: $TOTAL"
i=0
: > "$OUT_JSONL"
for f in "${FILES[@]}"; do
  i=$((i+1))
  if [[ ! -f "$f" ]]; then
    echo "[$i/$TOTAL] $f  ↳ SKIP (not a file)"
    continue
  fi
  process_file "$i" "$TOTAL" "$f"
done

echo "Done. Artifacts in: $BYFILE_DIR"
