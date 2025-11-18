#!/usr/bin/env bash
# Usage: ./crs_single_file_strict_v2.sh <file> [out.json]
set -euo pipefail

FILE="${1:-}"; OUT="${2:-userimp_findings.json}"
[[ -f "${FILE:-}" ]] || { echo "ERROR: file not found: $FILE" >&2; exit 1; }

ENDPOINT="${ENDPOINT:-http://127.0.0.1:8000/v1/crs/run}"
LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-600}"
LLM_TEMPERATURE="${LLM_TEMPERATURE:-0.0}"
TIMEOUT="${TIMEOUT:-600}"

WORK="$(mktemp -d)"
SRC="$WORK/src.txt"
nl -ba -- "$FILE" > "$SRC" || true

PAY="$WORK/payload.json"
HDR="$WORK/resp.headers"
RAW="$WORK/resp.body"
RAW2="$WORK/resp2.body"

python3 - "$FILE" "$SRC" "$LLM_MAX_TOKENS" "$LLM_TEMPERATURE" > "$PAY" <<'PY'
import json, sys
path, srcp, max_tokens, temperature = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
src=open(srcp,'r',encoding='utf-8',errors='ignore').read()
fewshot=[{"path":"example/Config.java","cwe_guess":"CWE-284 (Improper Access Control)","severity":"Medium","confidence":0.9,"lines":[42,49],"snippet":"if (isAdmin()) { return true; } // missing resource check","evidence":"Authorization decision without per-resource permission.","reasoning":"Maps to CWE-284.","fix":"Add resource-level permission check and fail closed."}]
system=("STRICT: Return ONLY a JSON array of findings (or []). No prose/markdown. "
        "Each item: {\"path\":\"…\",\"cwe_guess\":\"CWE-### (name)\",\"severity\":\"Low|Medium|High|Critical\","
        "\"confidence\":0.0,\"lines\":[start,end?],\"snippet\":\"…\",\"evidence\":\"…\",\"reasoning\":\"…\",\"fix\":\"…\"}.")
user=f"FILE: {path}\nCONTENT (1-based lines):\n\n{src}"
payload={"messages":[{"role":"system","content":system},{"role":"user","content":user},{"role":"assistant","content":json.dumps(fewshot)}],
         "stream": False, "llm_max_tokens": max_tokens, "llm_temperature": temperature}
print(json.dumps(payload))
PY

# Call webservice, capture headers and body
curl -sS --max-time "$TIMEOUT" -D "$HDR" -o "$RAW" \
  -H "Content-Type: application/json" -d @"$PAY" "$ENDPOINT" || true

echo "==> HTTP headers:"
sed -n '1,20p' "$HDR"

CODE=$(awk 'NR==1{print $2}' "$HDR")
if [[ -z "${CODE:-}" ]]; then
  echo "ERROR: no HTTP status line (empty response?). Body bytes: $(wc -c < "$RAW" 2>/dev/null || echo 0)" >&2
  echo "Raw preview:"; head -c 200 "$RAW" 2>/dev/null || true; echo
  exit 1
fi

if [[ "$CODE" != "200" ]]; then
  echo "ERROR: HTTP $CODE from service. Body preview:" >&2
  head -c 400 "$RAW" 2>/dev/null || true; echo
  exit 1
fi

# Try direct JSON decode (array or dict{findings})
python3 - "$RAW" "$OUT" > /dev/null 2>&1 <<'PY' || true
import json,sys
rawp,outp=sys.argv[1],sys.argv[2]
s=open(rawp,'r',errors='ignore').read().strip()
obj=json.loads(s)
if isinstance(obj,dict) and isinstance(obj.get("findings"),list): obj=obj["findings"]
if isinstance(obj,list):
    open(outp,'w').write(json.dumps(obj,indent=2)); print("WROTE",outp)
else:
    raise SystemExit(1)
PY

if [[ -s "$OUT" ]]; then
  echo "WROTE $OUT"
  rm -rf "$WORK"
  exit 0
fi

# Salvage path: extract assistant.content or last balanced array
python3 - "$RAW" "$RAW2" "$OUT" <<'PY'
import json,sys,re
rawp,raw2,outp=sys.argv[1],sys.argv[2],sys.argv[3]
s=open(rawp,'r',errors='ignore').read().strip()

# If service wrapped Ollama, sometimes: {"message":{"content":"..."}}
try:
    obj=json.loads(s)
    if isinstance(obj,dict):
        msg=obj.get("message") or {}
        c=msg.get("content")
        if isinstance(c,str) and c.strip():
            open(raw2,'w').write(c); s=c
except Exception:
    pass

def extract_last_array(txt):
    start=None; depth=0; last=None
    for i,ch in enumerate(txt):
        if ch=='[':
            if depth==0: start=i
            depth+=1
        elif ch==']':
            if depth>0:
                depth-=1
                if depth==0 and start is not None:
                    last=(start,i+1)
    if last:
        frag=txt[last[0]:last[1]]
        try:
            arr=json.loads(frag)
            if isinstance(arr,list):
                return arr
        except Exception:
            pass
    return None

arr=extract_last_array(s)
if arr is None:
    # also try object with 'findings'
    m=re.findall(r'\{[^{}]*"findings"\s*:\s*\[[\s\S]*?\][^{}]*\}', s)
    for frag in reversed(m):
        try:
            obj=json.loads(frag)
            if isinstance(obj,dict) and isinstance(obj.get("findings"),list):
                arr=obj["findings"]; break
        except Exception:
            pass

if arr is not None:
    open(outp,'w').write(json.dumps(arr,indent=2))
    print("WROTE", outp)
else:
    print("NO_JSON_ARRAY")
PY

if [[ -s "$OUT" ]]; then
  echo "WROTE $OUT"
  rm -rf "$WORK"
  exit 0
fi

echo "ERROR: service body was 200 OK but not valid JSON array. Raw preview:"
head -c 300 "$RAW" || true; echo
[[ -s "$RAW2" ]] && { echo "Assistant content preview:"; head -c 300 "$RAW2"; echo; }
echo "Hint: check service logs -> docker compose logs --no-color --tail=120 atlantis-webservice"
rm -rf "$WORK"
exit 1
