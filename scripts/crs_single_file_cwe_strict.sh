#!/usr/bin/env bash
# Strict CWE finder for a single file via Atlantis webservice (Ollama)
# Now with:
#   - Module verification inside the atlantis-webservice container
#   - Optional live logs from atlantis-webservice and ollama (SHOW_LOGS=1)
#
# Usage:
#   ./crs_single_file_cwe_strict.sh <path/to/file> [out.json]
#
# Env knobs (optional):
#   ENDPOINT=http://127.0.0.1:8000/v1/crs/run
#   LLM_MAX_TOKENS=900  LLM_TEMPERATURE=0  TIMEOUT=900
#   SHOW_LOGS=1     # live stream docker logs while running

set -euo pipefail

FILE="${1:-}"
OUT="${2:-findings.json}"
[[ -f "${FILE:-}" ]] || { echo "ERROR: file not found: $FILE" >&2; exit 1; }

: "${ENDPOINT:=http://127.0.0.1:8000/v1/crs/run}"
: "${LLM_MAX_TOKENS:=900}"
: "${LLM_TEMPERATURE:=0}"
: "${TIMEOUT:=900}"
: "${SHOW_LOGS:=0}"

WORK="$(mktemp -d)"
SRC="$WORK/src.txt"
LOGDIR="$WORK/logs"
mkdir -p "$LOGDIR"
nl -ba -- "$FILE" > "$SRC"

# ---- Optional live logs ----------------------------------------------------
if [[ "$SHOW_LOGS" == "1" ]]; then
  echo "==> Tailing docker logs (press Ctrl-C to stop the script)"
  # Start from now; write to files and stream to stdout
  { docker-compose logs -f --tail=0 atlantis-webservice | tee "$LOGDIR/webservice.log" & echo $! > "$WORK/.logpids"; } 2>/dev/null || true
  { docker-compose logs -f --tail=0 ollama              | tee "$LOGDIR/ollama.log"      & echo $! >> "$WORK/.logpids"; } 2>/dev/null || true
fi
cleanup() {
  if [[ -f "$WORK/.logpids" ]]; then
    while read -r p; do kill "$p" 2>/dev/null || true; done < "$WORK/.logpids"
  fi
}
trap cleanup EXIT

echo "WORKDIR: $WORK"

# ---- Print basic container status -----------------------------------------
echo "==> docker-compose ps"
docker compose ps || true

# ---- Verify Atlantis modules & config in the running container ------------
echo "==> Module files & provider config inside atlantis-webservice"
docker exec -i atlantis-webservice python - <<'PY' || true
import importlib, os, json
mods = [
  "aixcc.auth",
  "aixcc.providers.factory",
  "aixcc.providers.ollama_client",
]
info = {"modules":{}, "env":{}}
for m in mods:
    try:
        mod = importlib.import_module(m)
        info["modules"][m] = getattr(mod, "__file__", "<no-file>")
    except Exception as e:
        info["modules"][m] = f"<IMPORT-ERROR: {e}>"
for k in ["OLLAMA_URL","MODEL_NAME","OLLAMA_READ_TIMEOUT","OLLAMA_CONNECT_TIMEOUT"]:
    info["env"][k] = os.environ.get(k,"<unset>")
print(json.dumps(info, indent=2))
PY

# ---- Few-shot to force strict CWE JSON objects -----------------------------
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

# ---- Build strict request payload -----------------------------------------
python3 - "$FILE" "$SRC" "$FEWSHOT" "$LLM_MAX_TOKENS" "$LLM_TEMPERATURE" > "$WORK/payload.json" <<'PY'
import json, sys, os
path, srcp, fewshot, max_toks, temp = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), float(sys.argv[5])
src = open(srcp,'r',encoding='utf-8',errors='ignore').read()
user = f"Analyze this single file for concrete vulnerabilities and map to CWE. If no issues, return [].\n\nFILE: {path}\nCONTENT (1-based lines):\n{src}"
payload = {
  "messages": [
    {"role":"system","content": fewshot},
    {"role":"user","content": user}
  ],
  "stream": False,
  "format": "json",
  "llm_max_tokens": max_toks,
  "llm_temperature": temp
}
print(json.dumps(payload))
PY

echo "==> Request payload: $WORK/payload.json"
# Keep a copy for troubleshooting
cp "$WORK/payload.json" "$LOGDIR/payload.json" 2>/dev/null || true

# ---- Call the service (strict JSON expected) -------------------------------
HTTP="$WORK/http.txt"
BODY="$WORK/body.txt"

echo "==> Sending request to $ENDPOINT"
curl -sS -w "\n%{http_code}\n" --max-time "$TIMEOUT" \
  -H "Content-Type: application/json" \
  -d @"$WORK/payload.json" "$ENDPOINT" \
  | tee "$WORK/body.withcode" >/dev/null

tail -n1 "$WORK/body.withcode" | tr -d '\r\n' > "$HTTP"
sed '$d' "$WORK/body.withcode" > "$BODY" || true
rm -f "$WORK/body.withcode"

CODE="$(cat "$HTTP" 2>/dev/null || echo "?")"
echo "HTTP: $CODE"

# Save raw body for inspection
cp "$BODY" "$LOGDIR/raw_response.txt" 2>/dev/null || true

if [[ "$CODE" != "200" ]]; then
  echo "WARN: non-200 response. Writing raw body to $OUT"
  cat "$BODY" > "$OUT"
  echo "WROTE $OUT"
  exit 0
fi

# ---- Validate/pretty-print JSON; salvage if needed ------------------------
python3 - "$BODY" "$OUT" <<'PY'
import sys, json, re
rawp, outp = sys.argv[1], sys.argv[2]
s = open(rawp,'r',errors='ignore').read()

def parse_arr(x):
    try:
        j = json.loads(x)
        if isinstance(j, list): return j
        if isinstance(j, dict) and isinstance(j.get("findings"), list): return j["findings"]
    except: pass
    return None

arr = parse_arr(s)
if arr is None:
    # fenced JSON
    last=None
    for m in re.finditer(r"```json\s*([\s\S]*?)```", s, re.I): last = m.group(1)
    if last: arr = parse_arr(last)
if arr is None:
    # last array-like
    start=None; depth=0; last=None
    for i,ch in enumerate(s):
        if ch=='[':
            if depth==0: start=i
            depth+=1
        elif ch==']':
            if depth>0:
                depth-=1
                if depth==0 and start is not None: last=(start,i+1)
    if last: arr = parse_arr(s[last[0]:last[1]])

if arr is None:
    # give raw back (debug)
    open(outp,'w').write(s)
else:
    open(outp,'w').write(json.dumps(arr, indent=2))
PY

echo "WROTE $OUT"
echo "Logs & artifacts: $LOGDIR"
