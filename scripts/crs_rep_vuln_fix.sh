#!/usr/bin/env bash
# Robust repo scanner -> CRS (Atlantis webservice) -> Ollama
# Usage:
#   SHOW_LOGS=1 INCLUDE_PATHS="path1 path2" \
#   MAX_TOTAL_BYTES=120000 MAX_PER_FILE=20000 CHUNK_BYTES=7000 MAX_CHUNKS=10 \
#   LLM_MAX_TOKENS=256 TIMEOUT=900 \
#   ./crs_repo_vuln_fix.sh <repo_dir> "<focus prompt>" [out.json]
#
# Notes:
# - Never dies on grep/file non-zero due to guards (|| true)
# - Prints progress and HTTP code
# - If JSON is malformed, salvages best findings array; else writes raw

set -Eeuo pipefail

REPO="${1:-}"; FOCUS="${2:-security vulnerabilities}"; OUT="${3:-repo_findings.json}"
[[ -d "${REPO:-}" ]] || { echo "ERROR: repo not found: $REPO" >&2; exit 1; }

# Tunables (caller may override via env)
: "${ENDPOINT:=http://127.0.0.1:8000/v1/crs/run}"
: "${MAX_TOTAL_BYTES:=200000}"
: "${MAX_PER_FILE:=25000}"
: "${CHUNK_BYTES:=8000}"
: "${TOP_N:=80}"                 # max files to pack
: "${TIMEOUT:=600}"
: "${SHOW_LOGS:=0}"
: "${INCLUDE_PATHS:=}"
: "${LLM_MAX_TOKENS:=600}"

# Back-compat: if MAX_CHUNKS provided, use it as TOP_N
if [[ -n "${MAX_CHUNKS:-}" ]]; then TOP_N="${MAX_CHUNKS}"; fi

KW='(auth|authoriz|impersonat|kerberos|sasl|token|password|secret|key|credential|encrypt|decrypt|cipher|jwt|tls|ssl|truststore|keystore|cert|x509|permission|visibility|acl|access|vulnerab|security|signature|mac|hmac|sha1|md5|nonce|salt)'

WORK="$(mktemp -d)"
LOG="$WORK/run.log"; RAW="$WORK/raw.out"; CTX="$WORK/context.txt"; : > "$CTX"
PAY="$WORK/payload.json"
echo "WORKDIR: $WORK" | tee -a "$LOG"

# Optional: live tails (non-fatal if compose not present or services named differently)
if [[ "$SHOW_LOGS" == "1" ]]; then
  { docker compose logs -f --tail=0 atlantis-webservice & echo $! > "$WORK/.logpids"; } 2>/dev/null || true
  { docker compose logs -f --tail=0 ollama & echo $! >> "$WORK/.logpids"; } 2>/dev/null || true
fi
cleanup() {
  if [[ -f "$WORK/.logpids" ]]; then
    while read -r p; do kill "$p" 2>/dev/null || true; done < "$WORK/.logpids"
  fi
}
trap cleanup EXIT

cd "$REPO"

# Build file list
if [[ -n "$INCLUDE_PATHS" ]]; then
  mapfile -t ALLFILES < <(
    for p in $INCLUDE_PATHS; do
      find "$p" -type f -readable \
        ! -path "*/.git/*" ! -path "*/target/*" ! -path "*/build/*" \
        ! -path "*/dist/*" ! -path "*/out/*" ! -path "*/node_modules/*" \
        \( -name "*.java" -o -name "*.xml" -o -name "*.properties" -o -name "*.conf" -o -name "*.sh" \) \
        -size -"${MAX_PER_FILE}"c -print 2>/dev/null || true
    done | LC_ALL=C sort -u
  )
else
  mapfile -t ALLFILES < <(
    find . -type f -readable \
      ! -path "*/.git/*" ! -path "*/target/*" ! -path "*/build/*" \
      ! -path "*/dist/*" ! -path "*/out/*" ! -path "*/node_modules/*" \
      \( -name "*.java" -o -name "*.xml" -o -name "*.properties" -o -name "*.conf" -o -name "*.sh" \) \
      -size -"${MAX_PER_FILE}"c -print 2>/dev/null | LC_ALL=C sort
  )
fi
echo "==> Files considered: ${#ALLFILES[@]}" | tee -a "$LOG"

# Candidate selection (guard non-zero)
CAND=()
for f in "${ALLFILES[@]}"; do
  [[ -r "$f" ]] || continue
  file -b --mime "$f" 2>/dev/null | grep -qi 'charset=binary' && continue || true
  if grep -I -i -E -m1 "$KW" -- "$f" >/dev/null 2>&1; then
    CAND+=("$f")
  fi
  (( ${#CAND[@]} >= TOP_N )) && break || true
done
if (( ${#CAND[@]} == 0 )); then
  echo "==> No keyword hits; falling back to first $TOP_N files" | tee -a "$LOG"
  CAND=("${ALLFILES[@]:0:$TOP_N}")
fi
echo "==> Selecting ${#CAND[@]} candidate files" | tee -a "$LOG"

# Pack context respecting MAX_TOTAL_BYTES
used=0; added=0
for f in "${CAND[@]}"; do
  sz=$(wc -c < "$f" 2>/dev/null || echo 0)
  (( sz > MAX_PER_FILE )) && continue
  (( used + CHUNK_BYTES + 256 > MAX_TOTAL_BYTES )) && break
  {
    echo "===== FILE: $f ====="
    nl -ba -- "$f" | head -c "$CHUNK_BYTES" || true
    echo -e "\n"
  } >> "$CTX"
  used=$(( used + CHUNK_BYTES + 256 ))
  added=$(( added + 1 ))
done
echo "==> Packed $added files (≈${used} bytes) into context" | tee -a "$LOG"
[[ $added -gt 0 ]] || { echo "ERROR: context empty (caps too small?)" | tee -a "$LOG"; exit 2; }

# Build payload (streaming)
python3 - "$FOCUS" "$CTX" "$LLM_MAX_TOKENS" > "$PAY" <<'PY'
import json, sys
focus, ctxp, max_t = sys.argv[1], sys.argv[2], int(sys.argv[3])
ctx=open(ctxp,'r',encoding='utf-8',errors='ignore').read()
system=("You are an application security auditor. Prefer CWE mapping, file paths and line ranges. "
        "Output JSON if possible; prose is allowed.")
user=f"FOCUS: {focus}\n\nCONTEXT (files with 1-based lines):\n{ctx}"
payload={
  "messages":[{"role":"system","content":system},{"role":"user","content":user}],
  "stream": True,
  "llm_max_tokens": max_t
}
print(json.dumps(payload))
PY

echo "==> Requesting CRS (streaming)..." | tee -a "$LOG"

# Call service, capture HTTP code; do not crash on network error
HTTP_CODE=0
curl -sS -w "\n%{http_code}\n" --max-time "$TIMEOUT" \
  -H "Content-Type: application/json" \
  -d @"$PAY" "$ENDPOINT" \
  | tee "$RAW.withcode" >/dev/null || true
HTTP_CODE="$(tail -n1 "$RAW.withcode" | tr -d '\r\n' || true)"
sed '$d' "$RAW.withcode" > "$RAW" 2>/dev/null || true
rm -f "$RAW.withcode" || true
echo "==> HTTP code: ${HTTP_CODE:-?}" | tee -a "$LOG"

# Salvage best findings-like array; else keep raw body so you can inspect
python3 - "$RAW" "${OUT}" <<'PY'
import sys, json, re
REQUIRED={"path","cwe_guess","severity","confidence","lines","snippet","evidence","reasoning","fix"}
rawp,outp=sys.argv[1],sys.argv[2]
s=open(rawp,'r',errors='ignore').read()

def candidates(t):
    # try direct json
    try: yield json.loads(t)
    except: pass
    # wrappers
    try:
        obj=json.loads(t)
        if isinstance(obj,dict):
            for k in ("message","output","response","content","text"):
                v=obj.get(k)
                if isinstance(v,dict) and isinstance(v.get("content"),str): yield v["content"]
                elif isinstance(v,str): yield v
    except: pass
    # ```json ... ```
    for m in re.finditer(r"```json\s*([\s\S]*?)```", t, re.I): yield m.group(1)
    # {... "findings":[ ... ] ...}
    for m in re.finditer(r"\{[^{}]*\"findings\"\s*:\s*\[[\s\S]*?\][^{}]*\}", t): yield m.group(0)
    # many arrays
    arrays=[]; st=[]
    for i,ch in enumerate(t):
        if ch=='[': st.append(i)
        elif ch==']' and st:
            start=st.pop(); arrays.append(t[start:i+1])
            if len(arrays)>=60: break
    for frag in arrays: yield frag

def jload(x):
    if isinstance(x,(dict,list)): return x
    try: return json.loads(x)
    except: return None

def score(arr):
    if not isinstance(arr,list): return (-1,0)
    objs=[it for it in arr if isinstance(it,dict)]
    ok=sum(1 for it in objs if REQUIRED.issubset(getattr(it,'keys',lambda:[])()))
    return (ok,len(objs))

best=None; best_sc=(-1,0)
for c in candidates(s):
    obj=jload(c)
    arr=obj["findings"] if isinstance(obj,dict) and isinstance(obj.get("findings"),list) else obj
    sc=score(arr)
    if sc>best_sc: best_sc, best = sc, arr
if isinstance(best,list) and best_sc[0]>0:
    print(json.dumps(best,indent=2))
else:
    open(outp,'w').write(s)
    print("WROTE RAW", outp, file=sys.stderr)
PY

echo "==> Output: ${OUT}"
echo "==> Logs:   ${LOG}"
echo "==> Raw:    ${RAW}"
