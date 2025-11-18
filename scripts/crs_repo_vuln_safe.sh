#!/usr/bin/env bash
# Usage: SHOW_LOGS=1 INCLUDE_PATHS="sub/dir another/dir" ./crs_repo_vuln_safe.sh <repo_path> "<focus>" [out.json]
set -euo pipefail

REPO="${1:-}"; FOCUS="${2:-security vulnerabilities}"; OUT="${3:-repo_findings.json}"
[[ -d "${REPO:-}" ]] || { echo "ERROR: repo not found: $REPO" >&2; exit 1; }

: "${ENDPOINT:=http://127.0.0.1:8000/v1/crs/run}"
: "${MAX_TOTAL_BYTES:=200000}"
: "${MAX_PER_FILE:=25000}"
: "${CHUNK_BYTES:=8000}"
: "${TOP_N:=80}"
: "${TIMEOUT:=600}"
: "${SHOW_LOGS:=0}"
: "${INCLUDE_PATHS:=}"

KW='(auth|authoriz|impersonat|kerberos|sasl|token|password|secret|key|credential|encrypt|decrypt|cipher|jwt|tls|ssl|truststore|keystore|cert|x509|permission|visibility|acl|access|vulnerab|security|signature|mac|hmac|sha1|md5|nonce|salt)'

WORK="$(mktemp -d)"
LOG="$WORK/run.log"; RAW="$WORK/raw.out"; CTX="$WORK/context.txt"; : > "$CTX"
echo "WORKDIR: $WORK" | tee -a "$LOG"

# Optional live logs from containers (non-fatal if missing)
if [[ "$SHOW_LOGS" == "1" ]]; then
  { docker compose logs -f --tail=0 atlantis-webservice & echo $! > "$WORK/.logpids"; } || true
  { docker compose logs -f --tail=0 ollama & echo $! >> "$WORK/.logpids"; } || true
fi

cleanup() {
  if [[ -f "$WORK/.logpids" ]]; then
    while read -r p; do kill "$p" 2>/dev/null || true; done < "$WORK/.logpids"
  fi
}
trap cleanup EXIT

cd "$REPO"

# Build file list (restrict to INCLUDE_PATHS if provided)
if [[ -n "$INCLUDE_PATHS" ]]; then
  mapfile -t ALLFILES < <(
    for p in $INCLUDE_PATHS; do
      find "$p" -type f -readable ! -path "*/.git/*" ! -path "*/target/*" ! -path "*/build/*" \
        ! -path "*/dist/*" ! -path "*/out/*" ! -path "*/node_modules/*" \
        \( -name "*.java" -o -name "*.xml" -o -name "*.properties" -o -name "*.conf" -o -name "*.sh" \) \
        -size -"${MAX_PER_FILE}"c -print 2>/dev/null || true
    done | LC_ALL=C sort -u
  )
else
  mapfile -t ALLFILES < <(
    find . -type f -readable ! -path "*/.git/*" ! -path "*/target/*" ! -path "*/build/*" \
      ! -path "*/dist/*" ! -path "*/out/*" ! -path "*/node_modules/*" \
      \( -name "*.java" -o -name "*.xml" -o -name "*.properties" -o -name "*.conf" -o -name "*.sh" \) \
      -size -"${MAX_PER_FILE}"c -print 2>/dev/null | LC_ALL=C sort
  )
fi

echo "==> Files considered: ${#ALLFILES[@]}" | tee -a "$LOG"

# Candidate selection (guard greps so non-match doesn't abort)
CAND=()
for f in "${ALLFILES[@]}"; do
  [[ -r "$f" ]] || continue
  # Skip binary (don't fail if 'file' or grep return non-zero)
  file -b --mime "$f" 2>/dev/null | grep -qi 'charset=binary' && continue || true
  # Keyword sniff
  if grep -I -i -E -m1 "$KW" -- "$f" >/dev/null 2>&1; then
    CAND+=("$f")
  fi
  (( ${#CAND[@]} >= TOP_N )) && break || true
done

if (( ${#CAND[@]} == 0 )); then
  echo "==> No keyword candidates; falling back to first $TOP_N files" | tee -a "$LOG"
  CAND=("${ALLFILES[@]:0:$TOP_N}")
fi

echo "==> Selecting ${#CAND[@]} candidate files" | tee -a "$LOG"

# Pack context under size caps
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

echo "==> Packed $added files into context (bytes ~ $used)" | tee -a "$LOG"
[[ $added -gt 0 ]] || { echo "ERROR: context empty (caps too small?)" | tee -a "$LOG"; exit 2; }

# Build payload
PAY="$WORK/payload.json"
python3 - "$FOCUS" "$CTX" > "$PAY" <<'PY'
import json, sys
focus, ctxp = sys.argv[1], sys.argv[2]
ctx=open(ctxp,'r',encoding='utf-8',errors='ignore').read()
system=("You are an application security auditor. Prefer CWEs with file paths and line ranges. "
        "Return JSON if you can; otherwise free text is acceptable.")
user=f"FOCUS: {focus}\n\nCONTEXT (files with 1-based lines):\n{ctx}"
payload={"messages":[{"role":"system","content":system},{"role":"user","content":user}],
         "stream": True}
print(json.dumps(payload))
PY

echo "==> Requesting CRS (streaming)..." | tee -a "$LOG"

# Call service; capture HTTP code but don't crash on 500
HTTP_CODE=0
curl -sS -w "\n%{http_code}\n" --max-time "$TIMEOUT" \
  -H "Content-Type: application/json" \
  -d @"$PAY" "$ENDPOINT" \
  | tee "$RAW.withcode" >/dev/null || true
HTTP_CODE="$(tail -n1 "$RAW.withcode" | tr -d '\r\n' || true)"
sed '$d' "$RAW.withcode" > "$RAW" 2>/dev/null || true
rm -f "$RAW.withcode" || true
echo "==> HTTP code: ${HTTP_CODE:-?}" | tee -a "$LOG"

# Salvage best findings array; if none, keep raw so you can inspect
python3 - "$RAW" "${OUT}" <<'PY'
import sys, json, re

REQUIRED={"path","cwe_guess","severity","confidence","lines","snippet","evidence","reasoning","fix"}
rawp, outp = sys.argv[1], sys.argv[2]
s=open(rawp,'r',errors='ignore').read()

def json_candidates(text):
    try:
        yield json.loads(text)
    except: pass
    try:
        obj=json.loads(text)
        if isinstance(obj,dict):
            for k in ("message","output","response","content","text"):
                v=obj.get(k)
                if isinstance(v,dict) and isinstance(v.get("content"),str):
                    yield v["content"]
                elif isinstance(v,str):
                    yield v
    except: pass
    for m in re.finditer(r"```json\s*([\s\S]*?)```", text, re.I):
        yield m.group(1)
    for m in re.finditer(r"\{[^{}]*\"findings\"\s*:\s*\[[\s\S]*?\][^{}]*\}", text):
        yield m.group(0)
    arrays=[]; stack=[]
    for i,ch in enumerate(text):
        if ch=='[': stack.append(i)
        elif ch==']' and stack:
            start=stack.pop(); arrays.append(text[start:i+1])
            if len(arrays)>=40: break
    for frag in arrays: yield frag

def load_json(x):
    if isinstance(x,(dict,list)): return x
    try: return json.loads(x)
    except: return None

def score(arr):
    if not isinstance(arr,list): return (-1,0)
    objs=[it for it in arr if isinstance(it,dict)]
    ok=0
    for it in objs:
        if REQUIRED.issubset(it.keys()):
            ok+=1
    return (ok, len(objs))

best=None; best_sc=(-1,0)
for c in json_candidates(s):
    obj=load_json(c)
    arr=obj["findings"] if isinstance(obj,dict) and isinstance(obj.get("findings"),list) else obj
    sc=score(arr)
    if sc>best_sc: best_sc, best = sc, arr

if isinstance(best,list) and best_sc[0]>0:
    print(json.dumps(best, indent=2))
else:
    # write raw so caller can inspect
    open(outp,'w').write(s); print("WROTE RAW", outp, file=sys.stderr)
    sys.exit(0)
PY

echo "==> Output: ${OUT}"
echo "==> Logs:   ${LOG}"
echo "==> Raw:    ${RAW}"
