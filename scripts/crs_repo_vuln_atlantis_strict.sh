#!/usr/bin/env bash
set -euo pipefail
REPO="${1:-}"; OUT="${2:-accumulo_full_repo.json}"
[[ -d "${REPO:-}" ]] || { echo "ERROR: repo not found: $REPO" >&2; exit 1; }

TOP_N="${TOP_N:-200}"
MAX_PER_FILE="${MAX_PER_FILE:-60000}"
KW='(auth|authoriz|impersonat|kerberos|sasl|token|password|secret|key|credential|encrypt|decrypt|cipher|jwt|tls|ssl|truststore|keystore|cert|x509|permission|visibility|acl|access|vulnerab|security|signature|mac|hmac|sha1|md5|nonce|salt)'
LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-600}"
LLM_TEMPERATURE="${LLM_TEMPERATURE:-0.0}"
PER_FILE_MAX_FINDINGS="${PER_FILE_MAX_FINDINGS:-3}"
TIMEOUT="${TIMEOUT:-600}"
ENDPOINT="${ENDPOINT:-http://127.0.0.1:8000/v1/crs/run}"

WORK="$(mktemp -d)"; RESULTS="$WORK/results.jsonl"; : > "$RESULTS"
cd "$REPO"

mapfile -t ALLFILES < <(
  find . -type f -readable \
    ! -path "*/.git/*" ! -path "*/target/*" ! -path "*/build/*" \
    ! -path "*/node_modules/*" ! -path "*/dist/*" ! -path "*/out/*" \
    ! -name "*.jar" ! -name "*.war" ! -name "*.ear" \
    ! -name "*.zip" ! -name "*.tgz" ! -name "*.tar.gz" ! -name "*.gz" \
    \( -name "*.java" -o -name "*.kt" -o -name "*.scala" -o -name "*.xml" -o -name "*.properties" -o -name "*.conf" -o -name "*.sh" \) \
    -size -"${MAX_PER_FILE}"c -print | LC_ALL=C sort
)

CAND=()
for f in "${ALLFILES[@]}"; do
  [[ -r "$f" ]] || continue
  if grep -I -i -E -m1 "$KW" -- "$f" >/dev/null 2>&1; then CAND+=("$f"); fi
  (( ${#CAND[@]} >= TOP_N )) && break || true
done
(( ${#CAND[@]} == 0 )) && CAND=("${ALLFILES[@]:0:$TOP_N}")

echo "Auditing ${#CAND[@]} files (JSON-only, per-file)…"

idx=0
for f in "${CAND[@]}"; do
  ((idx++))
  SRC="$WORK/src_$(printf %05d $idx).txt"; nl -ba -- "$f" | head -c "$MAX_PER_FILE" > "$SRC" || true
  PAY="$WORK/payload_$(printf %05d $idx).json"; RESP="$WORK/resp_$(printf %05d $idx).json"

  python3 - "$f" "$SRC" "$LLM_MAX_TOKENS" "$LLM_TEMPERATURE" "$PER_FILE_MAX_FINDINGS" > "$PAY" <<'PY'
import json, sys
path, srcp, max_tokens, temperature, limit = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5])
src = open(srcp,'r',encoding='utf-8',errors='ignore').read()
fewshot=[{"path":"example/Config.java","cwe_guess":"CWE-284 (Improper Access Control)","severity":"Medium","confidence":0.9,"lines":[42,49],"snippet":"if (isAdmin()) { return true; } // missing resource check","evidence":"Decision without verifying subject permission on a specific resource.","reasoning":"Role-only check maps to CWE-284.","fix":"Enforce resource-level permission/visibility check; fail closed."}]
system=("STRICT: Return ONLY a JSON array of findings (or []). No prose/markdown. "
        "Each item: {\"path\":\"…\",\"cwe_guess\":\"CWE-### (name)\",\"severity\":\"Low|Medium|High|Critical\",\"confidence\":0.0,"
        "\"lines\":[start,end?],\"snippet\":\"…\",\"evidence\":\"…\",\"reasoning\":\"…\",\"fix\":\"…\"}.")
user=f"FILE: {path}\nCONTENT (1-based lines):\n\n{src}"
payload={"messages":[{"role":"system","content":system},{"role":"user","content":user},{"role":"assistant","content":json.dumps(fewshot)}],
         "stream": False, "llm_max_tokens": max_tokens, "llm_temperature": temperature}
print(json.dumps(payload))
PY

  # Call webservice; it enforces JSON-only + retries internally
  curl -sS --max-time "$TIMEOUT" -H "Content-Type: application/json" -d @"$PAY" "$ENDPOINT" > "$RESP"

  # Must be a JSON array or object with findings[]
  python3 - "$RESP" <<'PY' || { echo "SKIP $f (invalid JSON)"; continue; }
import json,sys
p=sys.argv[1]; s=open(p,'r',errors='ignore').read().strip()
obj=json.loads(s)
if isinstance(obj,dict) and isinstance(obj.get("findings"),list): obj=obj["findings"]
assert isinstance(obj,list), "not array"
open(p,'w').write(json.dumps(obj))
PY

  # Normalize and append to JSONL
  python3 - "$f" "$RESP" >> "$RESULTS" <<'PY'
import json,sys
path=sys.argv[1]; arr=json.load(open(sys.argv[2]))
for it in arr:
    if not isinstance(it,dict): continue
    it.setdefault("path", path)
    if isinstance(it.get("snippet"),str) and len(it["snippet"])>1200: it["snippet"]=it["snippet"][:1200]+"…"
    print(json.dumps(it))
PY

  echo "OK [$idx/${#CAND[@]}] $f"
done

python3 - "$RESULTS" > "$OUT" <<'PY'
import json,sys
items=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
print(json.dumps(items, indent=2))
PY

echo "WROTE $OUT"
rm -rf "$WORK"
