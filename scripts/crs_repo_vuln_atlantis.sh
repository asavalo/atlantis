#!/usr/bin/env bash
# Repo → Atlantis CRS → STRICT CWE JSON
# Usage:
#   ./crs_repo_vuln_atlantis.sh <repo_path> [out.json]
# Example:
#   ./crs_repo_vuln_atlantis.sh ~/accumulo ~/accumulo_full_repo.json

set -euo pipefail

REPO="${1:-}"
OUT="${2:-accumulo_full_repo.json}"
[[ -d "${REPO:-}" ]] || { echo "ERROR: repo not found: $REPO" >&2; exit 1; }

# ---- Tunables (conservative defaults) ----
MAX_TOTAL_BYTES="${MAX_TOTAL_BYTES:-400000}"
MAX_PER_FILE="${MAX_PER_FILE:-50000}"
CHUNK_BYTES="${CHUNK_BYTES:-16000}"
MAX_CHUNKS="${MAX_CHUNKS:-20}"
TOP_N="${TOP_N:-80}"                 # up to N candidate files
LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-600}"

# Security keyword prefilter
KW='(auth|authoriz|kerberos|token|password|secret|key|credential|encrypt|decrypt|cipher|jwt|tls|ssl|truststore|keystore|cert|x509|permission|visibility|acl|access|vulnerab|security|signature|mac|hmac|sha1|md5|nonce|salt)'

cd "$REPO"

# 1) Collect readable code files under size caps (skip build/archives)
mapfile -t ALLFILES < <(
  find . -type f -readable \
    ! -path "*/.git/*" ! -path "*/target/*" ! -path "*/build/*" \
    ! -path "*/node_modules/*" ! -path "*/dist/*" ! -path "*/out/*" \
    ! -name "*.jar" ! -name "*.war" ! -name "*.ear" \
    ! -name "*.zip" ! -name "*.tgz" ! -name "*.tar.gz" ! -name "*.gz" \
    \( -name "*.java" -o -name "*.kt" -o -name "*.scala" -o -name "*.xml" -o -name "*.properties" -o -name "*.conf" -o -name "*.sh" \) \
    -size -"${MAX_PER_FILE}"c -print | LC_ALL=C sort
)

# 2) Prefilter candidates by security keywords
CAND=()
for f in "${ALLFILES[@]}"; do
  [[ -r "$f" ]] || continue
  if grep -I -i -E -m1 "$KW" -- "$f" >/dev/null 2>&1; then
    CAND+=("$f")
  fi
  (( ${#CAND[@]} >= TOP_N )) && break || true
done
# Fallback if no keyword hits
(( ${#CAND[@]} == 0 )) && CAND=("${ALLFILES[@]:0:$TOP_N}")

# 3) Pack context (FILE markers help the model emit correct paths/lines)
TMPDIR="$(mktemp -d)"
CTX="$TMPDIR/context.txt"
: > "$CTX"
used=0
for f in "${CAND[@]}"; do
  [[ -r "$f" ]] || continue
  sz=$(wc -c < "$f" || echo 0)
  (( sz > MAX_PER_FILE )) && continue
  (( used + sz + 256 > MAX_TOTAL_BYTES )) && continue
  {
    echo "===== FILE: $f ====="
    # keep text only, trim to CHUNK_BYTES per chunk to encourage line refs
    head -c "$CHUNK_BYTES" -- "$f" || true
    echo -e "\n"
  } >> "$CTX"
  used=$(( used + CHUNK_BYTES + 256 ))
  # optional: stop if chunk limit hit
done

# 4) Build STRICT JSON-only request to Atlantis (no prose allowed)
PAYLOAD="$TMPDIR/payload.json"
python3 - "$REPO" "$CTX" "$LLM_MAX_TOKENS" > "$PAYLOAD" <<'PY'
import json, sys, os, re
repo = os.path.abspath(sys.argv[1])
ctxp = sys.argv[2]
max_tokens = int(sys.argv[3])
ctx = open(ctxp,'r',encoding='utf-8',errors='ignore').read()

system = (
  "You are an application security auditor. Analyze the provided repository snippets "
  "and return ONLY a JSON array of CWE findings with this exact schema:\n"
  "[{\n"
  '  "path": "<relative file path as seen in FILE markers>",\n'
  '  "cwe_guess": "CWE-### (name allowed)",\n'
  '  "severity": "Low|Medium|High|Critical",\n'
  '  "confidence": <0.0-1.0>,\n'
  '  "lines": [<startLine>, <optionalEndLine>],\n'
  '  "snippet": "<verbatim code excerpt>",\n'
  '  "evidence": "<short why this is risky>",\n'
  '  "reasoning": "<short rationale>",\n'
  '  "fix": "<minimal fix or patch suggestion>"\n'
  "}]\n"
  "Rules: Output must be VALID JSON. NO prose, NO markdown, NO backticks. "
  "If no issues, return []. Prefer access control, secrets, crypto, input validation."
)

user = (
  f"REPO_ROOT: {repo}\n"
  "CONTEXT: Lines are from files delimited by '===== FILE: <path> ====='. "
  "Use those paths in 'path'. Include line numbers when evident.\n\n"
  + ctx
)

payload = {
  "messages": [
    {"role":"system","content": system},
    {"role":"user","content": user}
  ],
  "stream": False,
  "llm_max_tokens": max_tokens
}
print(json.dumps(payload))
PY

# 5) Call local Atlantis CRS and write clean JSON
curl -s -H "Content-Type: application/json" \
  -d @"$PAYLOAD" http://127.0.0.1:8000/v1/crs/run \
  > "$OUT"

# 6) Validate JSON quickly; if invalid, try to salvage best fragment
python3 - "$OUT" <<'PY' || true
import sys, json, os
p=os.path.abspath(sys.argv[1])
s=open(p,'r',errors='ignore').read().strip()
ok=True
try:
  obj=json.loads(s)
except Exception:
  ok=False
if ok and isinstance(obj, (list,dict)):
  print(f"VALID JSON -> {p}")
  sys.exit(0)

# salvage: find last balanced array
depth=0; start=None; end=None
for i,ch in enumerate(s):
  if ch=='[':
    if depth==0: start=i
    depth+=1
  elif ch==']':
    depth-=1
    if depth==0 and start is not None:
      end=i+1
frag = s[start:end] if start is not None and end is not None else ""
try:
  obj=json.loads(frag)
  open(p,'w').write(json.dumps(obj, indent=2))
  print(f"SALVAGED ARRAY JSON -> {p}")
except Exception:
  print("ERROR: Output was not valid JSON and could not be salvaged.", file=sys.stderr)
  print(s[:400], file=sys.stderr)
  sys.exit(1)
PY

echo "WROTE  $OUT"
rm -rf "$TMPDIR"
