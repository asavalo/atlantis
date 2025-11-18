#!/usr/bin/env bash
# Usage: ./crs_single_file_legacy.sh <file> [out.json]
set -euo pipefail
FILE="${1:-}"; OUT="${2:-findings.json}"
[[ -f "${FILE:-}" ]] || { echo "ERROR: file not found: $FILE" >&2; exit 1; }

ENDPOINT="${ENDPOINT:-http://127.0.0.1:8000/v1/crs/run}"
TIMEOUT="${TIMEOUT:-600}"

WORK="$(mktemp -d)"
SRC="$WORK/src.txt"; nl -ba -- "$FILE" > "$SRC" || true
PAY="$WORK/payload.json"; RAW="$WORK/raw.out"

python3 - "$FILE" "$SRC" > "$PAY" <<'PY'
import json, sys
path, srcp = sys.argv[1], sys.argv[2]
src=open(srcp,'r',encoding='utf-8',errors='ignore').read()
system=("You are an application security auditor. Prefer CWEs. Include path and lines where evident. "
        "Return JSON if you can; otherwise free text is fine.")
user=f"FILE: {path}\nCONTENT (1-based lines):\n\n{src}"
payload={"messages":[{"role":"system","content":system},{"role":"user","content":user}],
         "stream": True}
print(json.dumps(payload))
PY

# Call webservice (streaming) and save raw body verbatim
curl -sS --max-time "$TIMEOUT" -H "Content-Type: application/json" -d @"$PAY" "$ENDPOINT" \
  | tee "$RAW" >/dev/null

# Best-effort: extract the last JSON array if present; else keep raw
python3 - "$RAW" "$OUT" <<'PY'
import sys, json
rawp,outp=sys.argv[1],sys.argv[2]
s=open(rawp,'r',errors='ignore').read()
start=None; depth=0; last=None
for i,ch in enumerate(s):
    if ch=='[':
        if depth==0: start=i
        depth+=1
    elif ch==']':
        if depth>0:
            depth-=1
            if depth==0 and start is not None:
                last=(start,i+1)
if last:
    frag=s[last[0]:last[1]]
    try:
        arr=json.loads(frag)
        if isinstance(arr,list):
            open(outp,'w').write(json.dumps(arr,indent=2)); print("WROTE",outp); sys.exit(0)
    except: pass
open(outp,'w').write(s); print("WROTE RAW",outp)
PY

echo "RAW: $RAW"
