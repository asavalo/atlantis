#!/usr/bin/env bash
set -euo pipefail

# Usage: crs_file_vuln.sh <path-to-file> [focus]
FILE="${1:-}"
FOCUS="${2:-hard-coded secrets, weak crypto, auth & input validation}"

if [[ -z "$FILE" ]]; then
  echo "Usage: $0 <path-to-file> [focus]" >&2
  exit 1
fi

# ------------ Tunables ------------
CHUNK_BYTES=${CHUNK_BYTES:-6000}   # ~6 KB per message
MAX_CHUNKS=${MAX_CHUNKS:-8}        # up to ~48 KB total
LLM_MAX_TOKENS=${LLM_MAX_TOKENS:-256}
SHOW_LOGS=${SHOW_LOGS:-0}          # set to 1 to tail live logs during the run
# ----------------------------------

# ---- live logs helpers (toggle with SHOW_LOGS=1) ----
_tail_pids_file() { echo "${WORKDIR}/.logpids"; }

tail_logs_start() {
  [[ "${SHOW_LOGS}" = "1" ]] || return 0
  docker-compose logs -f atlantis-webservice >"${WORKDIR}/web.log" 2>&1 & LPID1=$!
  docker-compose logs -f ollama               >"${WORKDIR}/ollama.log" 2>&1 & LPID2=$!
  echo "${LPID1} ${LPID2}" > "$(_tail_pids_file)"
  # stream both logs live to this TTY
  tail -n0 -f "${WORKDIR}/web.log" "${WORKDIR}/ollama.log" 2>/dev/null & LPID3=$!
  echo "$(cat "$(_tail_pids_file)") ${LPID3}" > "$(_tail_pids_file)"
}

tail_logs_stop() {
  [[ -f "$(_tail_pids_file)" ]] || return 0
  xargs -r kill < "$(_tail_pids_file)" >/dev/null 2>&1 || true
}
# -----------------------------------------------------

# ---- pretty printing helper (robust) ----
pretty_print_response() {
  local resp="$1"
  local out_raw
  out_raw="$(jq -r '.output // empty' < "$resp" 2>/dev/null || true)"

  # Case 1: .output exists and is valid JSON
  if [[ -n "$out_raw" ]] && echo "$out_raw" | jq . >/dev/null 2>&1; then
    echo "$out_raw" | jq .
    return 0
  fi

  # Case 2: try to find first {...} or [...] block inside .output and pretty-print
  if [[ -n "$out_raw" ]]; then
    echo "$out_raw" | python3 - <<'PY' || true
import sys, json, re
s=sys.stdin.read()
# try direct parse of a JSON-looking slice (first {...} or [...] block)
m=re.search(r'(\{.*\}|\[.*\])', s, flags=re.S)
if m:
    try:
        obj=json.loads(m.group(1))
        print(json.dumps(obj, indent=2))
        sys.exit(0)
    except Exception:
        pass
# try unescaping if it was a quoted/escaped JSON string
try:
    s2 = bytes(s, 'utf-8').decode('unicode_escape')
    obj=json.loads(s2)
    print(json.dumps(obj, indent=2))
    sys.exit(0)
except Exception:
    pass
# fallback: just print the raw text
print(s)
PY
    return 0
  fi

  # Case 3: pretty-print entire HTTP response if it's JSON
  if jq . "$resp" >/dev/null 2>&1; then
    jq . "$resp"
    return 0
  fi

  # Fallback
  cat "$resp"
}
# ---------------------------------------

FILE_EXPANDED="$(readlink -f "$FILE" 2>/dev/null || echo "$FILE")"
[[ -f "$FILE_EXPANDED" ]] || { echo "No such file: $FILE_EXPANDED"; exit 1; }

WORKDIR="$(mktemp -d)"
trap 'tail_logs_stop || true' EXIT
CTX="$WORKDIR/context.txt"
PAYLOAD_FILE="$WORKDIR/payload.json"
RESP="$WORKDIR/resp.json"
RESP_STATUS="$WORKDIR/resp.status"

# Build context
printf "===== PATH: %s =====\n" "$FILE_EXPANDED" > "$CTX"
cat "$FILE_EXPANDED" >> "$CTX"

# Split into chunks
split -b "$CHUNK_BYTES" -d -a 3 "$CTX" "$WORKDIR/chunk_" || true
mapfile -t CHUNK_FILES < <(ls -1 "$WORKDIR"/chunk_* 2>/dev/null | head -n "$MAX_CHUNKS")
N=${#CHUNK_FILES[@]}

# Build messages: system + chunks + task
TMPMSG="$WORKDIR/messages.jsonl"; :> "$TMPMSG"
jq -cn --arg focus "$FOCUS" '{
  role:"system",
  content: ("You are an application security engineer. Work ONLY from the provided code chunks. "+
            "Goal: identify likely vulnerabilities or weak patterns relevant to: "+$focus+". "+
            "Return ONLY a JSON array. Each item: {path,cwe_guess,severity,evidence,reasoning,fix,confidence}. "+
            "If nothing concrete, return [].")
}' >> "$TMPMSG"

i=1
for f in "${CHUNK_FILES[@]}"; do
  jq -cn --rawfile c "$f" --arg i "$i" --arg n "$N" --arg p "$FILE_EXPANDED" '{
    role:"user",
    content: ("Context chunk ("+$i+"/"+$n+") from "+$p+":\n\n"+$c)
  }' >> "$TMPMSG"
  i=$((i+1))
done

jq -cn --arg p "$FILE_EXPANDED" '{role:"user", content:("TASK: analyze "+$p+" and output ONLY the JSON array of findings.")}' >> "$TMPMSG"

MESSAGES="$(jq -s '.' "$TMPMSG")"
jq -n --argjson messages "$MESSAGES" '{messages:$messages, stream:true}' > "$PAYLOAD_FILE"

# ---- run with live logs and live stream from CRS ----
tail_logs_start

echo "==> Requesting CRS (streaming live output)..."
echo "--------------------------------------------------"

curl -N -s \
  -H "Content-Type: application/json" \
  -d @"$PAYLOAD_FILE" \
  http://127.0.0.1:8000/v1/crs/run | tee "$RESP"

echo
echo "--------------------------------------------------"
echo "==> Stream finished"
echo

tail_logs_stop


HTTP_CODE="$(cat "$RESP_STATUS" 2>/dev/null || echo "")"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "CRS returned HTTP ${HTTP_CODE:-??}"
  echo "---- raw body ----"
  cat "$RESP"
  exit 1
fi

# Pretty-print result
echo "==> Parsed output (if valid JSON):"
pretty_print_response "$RESP"

