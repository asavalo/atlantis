#!/usr/bin/env bash
# Usage: ./crs_single_file_strict.sh <file> [out.json]
set -euo pipefail
FILE="${1:-}"; OUT="${2:-userimp_findings.json}"
[[ -f "${FILE:-}" ]] || { echo "ERROR: file not found: $FILE" >&2; exit 1; }

ENDPOINT="${ENDPOINT:-http://127.0.0.1:8000/v1/crs/run}"
LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-600}"
LLM_TEMPERATURE="${LLM_TEMPERATURE:-0.0}"
TIMEOUT="${TIMEOUT:-600}"

WORK="$(mktemp -d)"
SRC="$WORK/src.txt"; nl -ba -- "$FILE" > "$SRC" || true
PAY="$WORK/payload.json"; RESP="$WORK/resp.json"

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

# Call webservice (which should already enforce JSON)
curl -sS --max-time "$TIMEOUT" -H "Content-Type: application/json" -d @"$PAY" "$ENDPOINT" > "$RESP"

# Accept array or {"findings":[...]} ; error if neither
python3 - "$RESP" "$OUT" <<'PY'
import json,sys
resp, outp = sys.argv[1], sys.argv[2]
s=open(resp,'r',errors='ignore').read().strip()
obj=json.loads(s)
if isinstance(obj, dict) and isinstance(obj.get("findings"), list): obj=obj["findings"]
if not isinstance(obj, list): 
    print("ERROR: service did not return a JSON array.", file=sys.stderr)
    print(s[:400], file=sys.stderr); raise SystemExit(1)
open(outp,'w').write(json.dumps(obj, indent=2))
print(f"WROTE {outp}")
PY

rm -rf "$WORK"
