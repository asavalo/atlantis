#!/usr/bin/env bash
set -euo pipefail

# CRS drilldown for a list of designated files (Java/C), one by one.
# - Streams progress to stdout
# - Saves raw responses and per-file JSON
# - Consolidates valid findings into JSONL (one JSON object per line)
#
# Usage:
#   crs_drilldown_list.sh OUT_JSONL FILE1 [FILE2 ...]
#   crs_drilldown_list.sh OUT_JSONL --from-file FILELIST.txt
#
# Env vars you can tweak:
#   API_URL=http://127.0.0.1:8000/v1/crs/run
#   MAX_BYTES_PER_FILE=90000   (cap bytes sent from each file)
#   MIN_BYTES_PER_FILE=8000
#   LLM_MAX_TOKENS=512
#   LLM_TEMPERATURE=0
#   RETRIES=2                  (on HTTP 500 reduce payload by half then retry)
#   SLEEP_BETWEEN=0.1         (seconds between files)

API_URL="${API_URL:-http://127.0.0.1:8000/v1/crs/run}"
MAX_BYTES_PER_FILE="${MAX_BYTES_PER_FILE:-90000}"
MIN_BYTES_PER_FILE="${MIN_BYTES_PER_FILE:-8000}"
LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-512}"
LLM_TEMPERATURE="${LLM_TEMPERATURE:-0}"
RETRIES="${RETRIES:-2}"
SLEEP_BETWEEN="${SLEEP_BETWEEN:-0.1}"

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 OUT_JSONL FILE1 [FILE2 ...] | $0 OUT_JSONL --from-file LIST.txt" >&2
  exit 1
fi

OUT_JSONL="$1"; shift

# Build list of files
FILES=()
if [[ "${1:-}" == "--from-file" ]]; then
  [[ $# -lt 2 ]] && { echo "Missing list file after --from-file" >&2; exit 1; }
  LIST="$2"; shift 2
  mapfile -t FILES < <(grep -vE '^\s*$|^\s*#' "$LIST")
else
  FILES=("$@")
fi

# Workdir & artifacts
#WORKDIR="$(mktemp -d)"
WORKDIR="${WORKDIR_OVERRIDE:-$(mktemp -d)}"

BYFILE_DIR="${WORKDIR}/vuln_by_file"
LOGDIR="${WORKDIR}/logs"
mkdir -p "$BYFILE_DIR" "$LOGDIR"
: > "$OUT_JSONL"

echo "WORKDIR: $WORKDIR"
echo "Per-file findings: $BYFILE_DIR"
echo "Output JSONL: $OUT_JSONL"
echo

mkdir -p "$BYFILE_DIR" "$LOGDIR"
touch "${BYFILE_DIR}/.alive" || { echo "ERROR: cannot write to $BYFILE_DIR"; exit 1; }

make_safe_name() {
  # robust, never-empty safe name from full path
  # requires coreutils base64 (present on Amazon Linux)
  printf '%s' "$1" | base64 | tr '/+' '__' | tr -d '='
}

# ---------------- helper.py (payload & salvage; LLM-truth only) ----------------
PYHELP="${WORKDIR}/helper.py"
cat > "${PYHELP}" <<'PY'
import sys, json, re, os

mode = sys.argv[1]

REQUIRED_KEYS = ["path","cwe_guess","severity","confidence","lines","snippet","evidence","reasoning","fix"]

def guess_lang(path):
  p = path.lower()
  if p.endswith('.java'): return 'java'
  if p.endswith('.c') or p.endswith('.h'): return 'c'
  return 'plain'

def try_arr(x):
  try:
    j = json.loads(x)
    if isinstance(j, list): return j
    if isinstance(j, dict) and isinstance(j.get("findings"), list): return j["findings"]
  except Exception:
    pass
  return None

def keep_llm_truth(arr, file_path):
  out = []
  for o in arr or []:
    if not isinstance(o, dict):
      continue
    if "path" not in o:
      o = {"path": file_path, **o}
    if not all(k in o for k in REQUIRED_KEYS):
      continue
    if not isinstance(o.get("lines"), list):
      continue
    out.append(o)
  return out

if mode == "make":
  # args: path content_file max_tokens temp
  path, cfile, max_toks, temp = sys.argv[2], sys.argv[3], int(sys.argv[4]), float(sys.argv[5])
  try:
    content = open(cfile,'r',encoding='utf-8',errors='ignore').read()
  except Exception:
    content = ""
  lang = guess_lang(path)
  sysmsg = (
    "You are a strict vulnerability triage agent for a SINGLE source file.\n"
    "Return ONLY a JSON array (no wrapper object, no prose) where each item has ALL of these keys:\n"
    "path, cwe_guess (e.g. 'CWE-79'), severity ('Low'|'Medium'|'High'), confidence (0..1), "
    "lines (array of integers), snippet (short code excerpt), evidence, reasoning, fix.\n"
    "Every value must be derived from the file's content (NO placeholders/defaults). "
    "If you are not certain of a concrete issue, return an empty array []."
  )
  usr = {
    "task": "vuln-scan",
    "scope": "single-file",
    "target_path": path,
    "language": lang,
    "allowed_languages": ["java","c"],
    "rules": {"json_only": True, "no_prose": True, "require_all_fields": True, "max_items": 20}
  }
  payload = {
    "mode": "multilang",
    "format": "json",
    "stream": False,
    "llm_max_tokens": max_toks,
    "llm_temperature": temp,
    "messages": [
      {"role":"system","content":sysmsg},
      {"role":"user","content":json.dumps(usr,ensure_ascii=False)},
      {"role":"user","content":content}
    ]
  }
  print(json.dumps(payload,ensure_ascii=False)); sys.exit(0)

# salvage
raw_path = sys.argv[2]; file_path = sys.argv[3]
try:
  raw = open(raw_path,'r',errors='ignore').read()
except Exception:
  print("[]"); sys.exit(0)

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
if not isinstance(arr, list):
  arr = []
arr = keep_llm_truth(arr, file_path)
print(json.dumps(arr, ensure_ascii=False))
PY
# ------------------------------------------------------------------------------

health() {
  curl -sf "${API_URL%/v1/crs/run}/healthz" >/dev/null && echo "OK webservice healthy" || { echo "Webservice not healthy"; exit 1; }
}

make_payload() {
  local file="$1" tmp="$2"
  local cap="$3"
  head -c "$cap" "$file" > "$tmp.body" 2>/dev/null || : > "$tmp.body"
  python3 "${PYHELP}" make "$file" "$tmp.body" "$LLM_MAX_TOKENS" "$LLM_TEMPERATURE"
}

post_payload() {
  local payload="$1" out_prefix="$2"
  local code
  code="$(curl -sS -w '%{http_code}' -o "${out_prefix}.data" \
    -H 'Content-Type: application/json' \
    --max-time 300 \
    -X POST "$API_URL" \
    --data-binary @"$payload" \
    || echo "000")"
  echo "$code"
}

process_file() {
  local idx="$1" total="$2" f="$3"
  local cap="${MAX_BYTES_PER_FILE}"
  local tmp; tmp="$(mktemp -d "${WORKDIR}/one.XXXX")"
  local rel safe pff raw outarr httpcode payload_copy

  rel="$f"
  safe="$(make_safe_name "$rel")"
  pff="${BYFILE_DIR}/${safe}.json"
  raw="${BYFILE_DIR}/${safe}.raw.txt"
  httpcode="${BYFILE_DIR}/${safe}.httpcode"
  payload_copy="${BYFILE_DIR}/${safe}.payload.json"
  outarr="${tmp}/arr.json"

  echo "[$idx/$total] ${f}"
  # prove we can write per-file now
  : > "$httpcode" || { echo "   ↳ ERROR: cannot write $httpcode"; return 1; }

  local attempt=0
  while :; do
    # build payload (kept for debugging)
    head -c "$cap" "$f" > "${tmp}/body" 2>/dev/null || : > "${tmp}/body"
    python3 "${PYHELP}" make "$f" "${tmp}/body" "$LLM_MAX_TOKENS" "$LLM_TEMPERATURE" \
      > "${tmp}/payload.json"

    cp "${tmp}/payload.json" "$payload_copy" 2>/dev/null || :

    # call API
    local code
    code="$(curl -sS -w '%{http_code}' -o "${tmp}/resp.data" \
      -H 'Content-Type: application/json' \
      --max-time 300 \
      -X POST "$API_URL" \
      --data-binary @"${tmp}/payload.json" 2>/dev/null || echo "000")"

    # ALWAYS record artifacts
    echo -n "$code" > "$httpcode" || true
    cp "${tmp}/resp.data" "$raw" 2>/dev/null || :  # raw body

    if [[ "$code" == "200" ]]; then
      # salvage → array
      python3 "${PYHELP}" salvage "${tmp}/resp.data" "$f" > "$outarr" || echo "[]" > "$outarr"

      # write per-file JSON & append JSONL
      python3 - "$outarr" "$pff" >> "$OUT_JSONL" <<'PY'
import sys, json
arr_in, pff = sys.argv[1], sys.argv[2]
try:
  data = json.load(open(arr_in,'r'))
  if not isinstance(data, list): data=[]
except Exception:
  data=[]
with open(pff,'w',encoding='utf-8') as f:
  json.dump(data, f, ensure_ascii=False)
for o in data:
  print(json.dumps(o, ensure_ascii=False))
PY

      # count findings (avoid heredoc in command subst)
      local n
      n=$(python3 -c 'import sys,json; p=sys.argv[1]; 
try:
  a=json.load(open(p,"r"))
  print(len(a) if isinstance(a,list) else 0)
except Exception:
  print(0)' "$outarr")
      echo "   ↳ findings: ${n}"
      break
    fi

    if [[ "$code" == "500" || "$code" == "502" || "$code == 504" ]]; then
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
  sleep "${SLEEP_BETWEEN}"
}

# -------- run --------
health
TOTAL="${#FILES[@]}"
echo "Designated files: ${TOTAL}"
i=0
for f in "${FILES[@]}"; do
  ((i++))
  [[ -f "$f" ]] || { echo "   (skip missing) $f"; continue; }
  # only Java/C/H to match your use-case
  case "$f" in
    *.java|*.c|*.h) process_file "$i" "$TOTAL" "$f" ;;
    *) echo "   (skip non-java/c) $f" ;;
  esac
done

echo
echo "Done. Consolidated JSONL: $OUT_JSONL"
echo "Per-file artifacts: $BYFILE_DIR"
echo "Logs: $LOGDIR"
