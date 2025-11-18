#!/usr/bin/env bash
# Usage: ./crs_repo_vuln_legacy.sh <repo_path> "<focus prompt>" [out.json]
set -euo pipefail
REPO="${1:-}"; FOCUS="${2:-security vulnerabilities}"; OUT="${3:-repo_findings.json}"
[[ -d "${REPO:-}" ]] || { echo "ERROR: repo not found: $REPO" >&2; exit 1; }

ENDPOINT="${ENDPOINT:-http://127.0.0.1:8000/v1/crs/run}"
MAX_TOTAL_BYTES="${MAX_TOTAL_BYTES:-200000}"
MAX_PER_FILE="${MAX_PER_FILE:-25000}"
CHUNK_BYTES="${CHUNK_BYTES:-8000}"
TOP_N="${TOP_N:-80}"
TIMEOUT="${TIMEOUT:-600}"

KW='(auth|authoriz|impersonat|kerberos|sasl|token|password|secret|key|credential|encrypt|decrypt|cipher|jwt|tls|ssl|truststore|keystore|cert|x509|permission|visibility|acl|access|vulnerab|security|signature|mac|hmac|sha1|md5|nonce|salt)'

WORK="$(mktemp -d)"
RAW="$WORK/raw.out"; LOG="$WORK/run.log"; CTX="$WORK/context.txt"; : > "$CTX"

cd "$REPO"
mapfile -t ALLFILES < <(
  find . -type f -readable \
    ! -path "*/.git/*" ! -path "*/target/*" ! -path "*/build/*" \
    ! -path "*/dist/*" ! -path "*/out/*" ! -path "*/node_modules/*" \
    \( -name "*.java" -o -name "*.xml" -o -name "*.properties" -o -name "*.conf" -o -name "*.sh" \) \
    -size -"${MAX_PER_FILE}"c -print | LC_ALL=C sort
)

CAND=()
for f in "${ALLFILES[@]}"; do
  [[ -r "$f" ]] || continue
  if grep -I -i -E -m1 "$KW" -- "$f" >/dev/null 2>&1; then CAND+=("$f"); fi
  (( ${#CAND[@]} >= TOP_N )) && break || true
done
(( ${#CAND[@]} == 0 )) && CAND=("${ALLFILES[@]:0:$TOP_N}")

echo "==> Selecting ${#CAND[@]} candidate files" | tee -a "$LOG"

used=0
for f in "${CAND[@]}"; do
  sz=$(wc -c < "$f" || echo 0)
  (( sz > MAX_PER_FILE )) && continue
  (( used + CHUNK_BYTES + 256 > MAX_TOTAL_BYTES )) && continue
  {
    echo "===== FILE: $f ====="
    nl -ba -- "$f" | head -c "$CHUNK_BYTES" || true
    echo -e "\n"
  } >> "$CTX"
  used=$(( used + CHUNK_BYTES + 256 ))
done

PAY="$WORK/payload.json"
python3 - "$FOCUS" "$CTX" > "$PAY" <<'PY'
import json, sys
focus, ctxp = sys.argv[1], sys.argv[2]
ctx=open(ctxp,'r',encoding='utf-8',errors='ignore').read()
system=("You are an application security auditor. Prefer CWEs with file paths and line ranges when obvious. "
        "Return JSON if you can; otherwise free text is fine.")
user=f"FOCUS: {focus}\n\nCONTEXT (files with 1-based lines):\n{ctx}"
payload={"messages":[{"role":"system","content":system},{"role":"user","content":user}],
         "stream": True}
print(json.dumps(payload))
PY

echo "==> Requesting CRS (streaming)…" | tee -a "$LOG"
curl -sS --max-time "$TIMEOUT" -H "Content-Type: application/json" -d @"$PAY" "$ENDPOINT" \
  | tee "$RAW" >/dev/null

# Best-effort: extract last JSON array; else keep raw
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
