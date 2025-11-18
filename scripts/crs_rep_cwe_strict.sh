#!/usr/bin/env bash
# Strict CWE finder across a repo via your Atlantis webservice (Ollama)
# - Batches files to avoid oversized payloads / timeouts
# - Forces JSON mode, temp=0, stream=false
# - Few-shot example to steer model toward CWE findings
# - Salvages/merges findings, pretty-prints one final JSON
#
# Usage:
#   SHOW_LOGS=1 INCLUDE_PATHS="path1 path2" EXCLUDE_PATHS=".git target build" \
#   MAX_TOTAL_BYTES=120000 CHUNK_BYTES=7000 BATCH_FILES=10 \
#   LLM_MAX_TOKENS=700 TIMEOUT=900 \
#   ./crs_repo_cwe_strict.sh <repo_dir> "<focus prompt>" [out.json]
#
# Example:
#   SHOW_LOGS=1 INCLUDE_PATHS="core/src main/" \
#   ./crs_repo_cwe_strict.sh ~/accumulo \
#     "access control, authentication, authorization, secrets handling" \
#     ~/accumulo_full_repo.json

set -Eeuo pipefail

REPO="${1:-}"; FOCUS="${2:-security vulnerabilities}"; OUT="${3:-repo_findings.json}"
[[ -d "${REPO:-}" ]] || { echo "ERROR: repo not found: $REPO" >&2; exit 1; }

# Tunables (caller may override via env)
: "${ENDPOINT:=http://127.0.0.1:8000/v1/crs/run}"
: "${LLM_MAX_TOKENS:=700}"
: "${LLM_TEMPERATURE:=0}"
: "${TIMEOUT:=900}"

: "${MAX_TOTAL_BYTES:=120000}"    # cap per batch (context text bytes)
: "${CHUNK_BYTES:=7000}"          # bytes per file snippet (head of file)
: "${BATCH_FILES:=10}"            # max files per batch
: "${MAX_PER_FILE:=25000}"        # skip very large files
: "${TOP_N:=200}"                 # max candidate files overall (keeps runs bounded)

: "${SHOW_LOGS:=0}"
: "${INCLUDE_PATHS:=}"            # e.g. "core/src server/"
: "${EXCLUDE_PATHS:=.git target build dist out node_modules .mvn .github}"  # space-separated
: "${FILE_GLOBS:=*.java *.xml *.properties *.conf *.sh *.yaml *.yml *.gradle pom.xml}"  # include set

KW='(auth|authoriz|impersonat|kerberos|sasl|token|password|secret|key|credential|encrypt|decrypt|cipher|jwt|tls|ssl|truststore|keystore|cert|x509|permission|visibility|acl|access|vulnerab|security|signature|mac|hmac|sha1|md5|nonce|salt)'

WORK="$(mktemp -d)"
LOG="$WORK/run.log"
ALLJSON="$WORK/all.jsonl"
: > "$ALLJSON"
echo "WORKDIR: $WORK" | tee -a "$LOG"

# Optional: live tails of the two containers (non-fatal if not present)
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

# ---------- Build file list ----------
exclude_expr=()
for e in $EXCLUDE_PATHS; do exclude_expr+=( -not -path "*/$e/*" ); done

# include roots
if [[ -n "$INCLUDE_PATHS" ]]; then
  # Collect per include root
  mapfile -t ALLFILES < <(
    for root in $INCLUDE_PATHS; do
      for g in $FILE_GLOBS; do
        find "$root" -type f -readable "${exclude_expr[@]}" -name "$g" -size -"${MAX_PER_FILE}"c -print 2>/dev/null || true
      done
    done | LC_ALL=C sort -u
  )
else
  # Whole repo
  mapfile -t ALLFILES < <(
    for g in $FILE_GLOBS; do
      find . -type f -readable "${exclude_expr[@]}" -name "$g" -size -"${MAX_PER_FILE}"c -print 2>/dev/null || true
    done | LC_ALL=C sort -u
  )
fi
echo "==> Files considered: ${#ALLFILES[@]}" | tee -a "$LOG"

# Keyword-filtered candidates (don’t crash on non-zero grep)
CAND=()
for f in "${ALLFILES[@]}"; do
  [[ -r "$f" ]] || continue
  file -b --mime "$f" 2>/dev/null | grep -qi 'charset=binary' && continue || true
  if grep -I -i -E -m1 "$KW" -- "$f" >/dev/null 2>&1; then
    CAND+=("$f")
  fi
  (( ${#CAND[@]} >= TOP_N )) && break || true
done

# Fallback if no keyword hits
if (( ${#CAND[@]} == 0 )); then
  echo "==> No keyword hits; taking first $TOP_N files" | tee -a "$LOG"
  CAND=("${ALLFILES[@]:0:$TOP_N}")
fi
echo "==> Candidate files: ${#CAND[@]}" | tee -a "$LOG"

# ---------- Few-shot prompt ----------
read -r -d '' FEWSHOT <<'FS'
You are an application security auditor. Identify concrete vulnerabilities and map to CWEs.

Return ONLY a JSON array ([] if none). Each item must have:
{
  "path": "<file path>",
  "cwe_guess": "CWE-### (Name)",
  "severity": "Low|Medium|High|Critical",
  "confidence": 0.0-1.0,
  "lines": [start, end?],
  "snippet": "<short code excerpt>",
  "evidence": "<why this code is vulnerable, 1-2 sentences>",
  "reasoning": "<concise reasoning>",
  "fix": "<minimal patch or remediation>"
}

Example (different file):
INPUT (numbered):
1: String pwd = "s3cret";
2: MessageDigest md = MessageDigest.getInstance("MD5");
3: String url = request.getParameter("redirect");
4: response.sendRedirect(url);

EXPECTED JSON:
[
  {"path":"Example.java","cwe_guess":"CWE-259 (Use of Hard-coded Password)","severity":"High","confidence":0.9,"lines":[1],"snippet":"String pwd = \"s3cret\";","evidence":"Credential is embedded.","reasoning":"Hard-coded password present.","fix":"Remove secret; load from secure store and rotate."},
  {"path":"Example.java","cwe_guess":"CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)","severity":"Medium","confidence":0.85,"lines":[2],"snippet":"MessageDigest.getInstance(\"MD5\");","evidence":"MD5 is cryptographically broken.","reasoning":"Deprecated hash used.","fix":"Use SHA-256 or a modern KDF."},
  {"path":"Example.java","cwe_guess":"CWE-601 (Open Redirect)","severity":"Medium","confidence":0.7,"lines":[3,4],"snippet":"String url = request.getParameter(\"redirect\");\nresponse.sendRedirect(url);","evidence":"Unvalidated user URL to redirect.","reasoning":"No allowlist/validation.","fix":"Validate destination against allowlist or use relative redirects."}
]
FS

# ---------- Batch over candidates ----------
batch_idx=0
total_found=0

make_payload() {  # args: <ctxfile> -> payload to stdout
  python3 - "$FOCUS" "$1" "$FEWSHOT" "$LLM_MAX_TOKENS" "$LLM_TEMPERATURE" <<'PY'
import json, sys
focus, ctxp, fewshot, max_toks, temp = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), float(sys.argv[5])
ctx=open(ctxp,'r',encoding='utf-8',errors='ignore').read()
user=f"Analyze these files for concrete vulnerabilities mapped to CWE. If none, return [].\n\nCONTEXT (files with 1-based lines):\n{ctx}"
payload={
  "messages":[{"role":"system","content":fewshot},{"role":"user","content":user}],
  "stream": False,
  "format": "json",
  "llm_max_tokens": max_toks,
  "llm_temperature": temp
}
print(json.dumps(payload))
PY
}

salvage_to_jsonl() {  # args: <bodyfile> -> writes per-item compact JSON to $ALLJSON
  python3 - "$1" "$ALLJSON" <<'PY'
import sys, json, re
rawp, outp = sys.argv[1], sys.argv[2]
s=open(rawp,'r',errors='ignore').read()

def try_array(x):
  try:
    j=json.loads(x)
    if isinstance(j,list): return j
    if isinstance(j,dict) and isinstance(j.get("findings"),list): return j["findings"]
  except: pass
  return None

arr = try_array(s)
if arr is None:
  # fenced
  last=None
  for m in re.finditer(r"```json\s*([\s\S]*?)```", s, re.I): last=m.group(1)
  if last: arr = try_array(last)
if arr is None:
  # last [...]
  start=None; depth=0; last=None
  for i,ch in enumerate(s):
    if ch=='[':
      if depth==0: start=i
      depth+=1
    elif ch==']':
      if depth>0:
        depth-=1
        if depth==0 and start is not None: last=(start,i+1)
  if last: arr = try_array(s[last[0]:last[1]])

if isinstance(arr,list):
  for it in arr:
    if isinstance(it,dict):
      print(json.dumps(it))
PY
}

batch_files=()
batch_bytes=0
pack_and_send_batch() {
  local ctx="$WORK/ctx_${batch_idx}.txt"
  : > "$ctx"
  local added=0; local used=0
  for f in "${batch_files[@]}"; do
    {
      echo "===== FILE: $f ====="
      nl -ba -- "$f" | head -c "$CHUNK_BYTES" || true
      echo -e "\n"
    } >> "$ctx"
    used=$(( used + CHUNK_BYTES + 256 ))
    added=$(( added + 1 ))
  done

  echo "==> Batch $batch_idx: files=$added, ~${used} bytes" | tee -a "$LOG"
  local pay="$WORK/payload_${batch_idx}.json"
  make_payload "$ctx" > "$pay"

  local body="$WORK/body_${batch_idx}.txt"
  local http="$WORK/http_${batch_idx}.txt"

  curl -sS -w "\n%{http_code}\n" --max-time "$TIMEOUT" \
    -H "Content-Type: application/json" \
    -d @"$pay" "$ENDPOINT" \
    | tee "$body.withcode" >/dev/null
  tail -n1 "$body.withcode" | tr -d '\r\n' > "$http"
  sed '$d' "$body.withcode" > "$body" || true
  rm -f "$body.withcode"

  local code; code="$(cat "$http" 2>/dev/null || echo '?')"
  echo "    HTTP $code" | tee -a "$LOG"

  if [[ "$code" == "200" ]]; then
    salvage_to_jsonl "$body"
  else
    echo "    WARN: non-200; keeping raw at $body" | tee -a "$LOG"
  fi
}

# Walk candidates and fill batches under caps
for f in "${CAND[@]}"; do
  # add file if readable and small-ish
  [[ -r "$f" ]] || continue
  sz=$(wc -c < "$f" 2>/dev/null || echo 0)
  (( sz > MAX_PER_FILE )) && continue

  # would this file push batch over caps?
  est=$(( batch_bytes + CHUNK_BYTES + 256 ))
  if (( ${#batch_files[@]} >= BATCH_FILES || est > MAX_TOTAL_BYTES )); then
    (( ${#batch_files[@]} > 0 )) && { batch_idx=$((batch_idx+1)); pack_and_send_batch; }
    batch_files=(); batch_bytes=0
  fi

  batch_files+=( "$f" )
  batch_bytes=$(( batch_bytes + CHUNK_BYTES + 256 ))
done

# flush last batch
if (( ${#batch_files[@]} > 0 )); then
  batch_idx=$((batch_idx+1)); pack_and_send_batch
fi

# ---------- Merge & de-dup ----------
python3 - "$ALLJSON" > "$OUT" <<'PY'
import sys, json, hashlib
items=[]
for line in open(sys.argv[1],'r',errors='ignore'):
  line=line.strip()
  if not line: continue
  try:
    it=json.loads(line)
    if isinstance(it,dict): items.append(it)
  except: pass

def key(it):
  sn=(it.get('snippet') or '')[:200]
  lines=tuple(it.get('lines') or [])
  return (it.get('path',''), lines, it.get('cwe_guess',''), hashlib.md5(sn.encode('utf-8','ignore')).hexdigest()[:8])

uniq={}
for it in items:
  uniq[key(it)] = it

out = sorted(uniq.values(), key=lambda x: float(x.get('confidence',0.0)), reverse=True)
print(json.dumps(out, indent=2))
PY

jq -r 'length as $n | "findings=\($n)"' "$OUT" 2>/dev/null || true
echo "WROTE $OUT"
echo "WORKDIR $WORK (logs & intermediates)"
