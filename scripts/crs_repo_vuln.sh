#!/usr/bin/env bash
set -euo pipefail

# crs_repo_vuln.sh — run CRS against (part of) a git repo
# Usage:
#   SHOW_LOGS=1 INCLUDE_PATHS="dir1 dir2" \
#   MAX_TOTAL_BYTES=120000 MAX_PER_FILE=20000 CHUNK_BYTES=7000 MAX_CHUNKS=10 \
#   LLM_MAX_TOKENS=256 \
#   ./crs_repo_vuln.sh <git-url-or-local-path> [focus-text]

REPO_SPEC="${1:-}"
FOCUS="${2:-authentication, TLS/SSL, secrets handling}"

if [[ -z "$REPO_SPEC" ]]; then
  echo "Usage: $0 <git-url-or-local-path> [focus]" >&2
  exit 1
fi

# ------------ Tunables (override via env) ------------
MAX_TOTAL_BYTES=${MAX_TOTAL_BYTES:-120000}
MAX_PER_FILE=${MAX_PER_FILE:-20000}
CHUNK_BYTES=${CHUNK_BYTES:-7000}
MAX_CHUNKS=${MAX_CHUNKS:-10}
LLM_MAX_TOKENS=${LLM_MAX_TOKENS:-256}
SHOW_LOGS=${SHOW_LOGS:-0}          # 1 = tail live docker logs during the run
INCLUDE_PATHS="${INCLUDE_PATHS:-}" # space-separated repo subpaths to focus
# -----------------------------------------------------

# Pick docker compose command compatible with your host
if command -v docker &>/dev/null && docker compose version &>/dev/null; then
  DC=(docker compose)
elif command -v docker-compose &>/dev/null; then
  DC=(docker-compose)
else
  echo "ERROR: docker compose not found (need 'docker compose' or 'docker-compose')" >&2
  exit 1
fi

# ---- live logs helpers (toggle with SHOW_LOGS=1) ----
WORKDIR="$(mktemp -d)"
trap '[[ -f "$(_tail_pids_file)" ]] && xargs -r kill < "$(_tail_pids_file)" >/dev/null 2>&1 || true' EXIT

_tail_pids_file() { echo "${WORKDIR}/.logpids"; }

tail_logs_start() {
  [[ "${SHOW_LOGS}" = "1" ]] || return 0
  "${DC[@]}" logs -f atlantis-webservice >"${WORKDIR}/web.log" 2>&1 & LPID1=$!
  "${DC[@]}" logs -f ollama               >"${WORKDIR}/ollama.log" 2>&1 & LPID2=$!
  echo "${LPID1} ${LPID2}" > "$(_tail_pids_file)"
  # stream to current TTY
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

  # Case 2: extract first {...} or [...] block / try unescape
  if [[ -n "$out_raw" ]]; then
    echo "$out_raw" | python3 - <<'PY' || true
import sys, json, re
s=sys.stdin.read()
m=re.search(r'(\{.*\}|\[.*\])', s, flags=re.S)
if m:
    try:
        print(json.dumps(json.loads(m.group(1)), indent=2))
        sys.exit(0)
    except Exception:
        pass
try:
    s2 = bytes(s, 'utf-8').decode('unicode_escape')
    print(json.dumps(json.loads(s2), indent=2))
    sys.exit(0)
except Exception:
    pass
print(s)
PY
    return 0
  fi

  # Case 3: pretty-print full HTTP response if JSON
  if jq . "$resp" >/dev/null 2>&1; then
    jq . "$resp"
    return 0
  fi

  # Fallback: raw
  cat "$resp"
}
# ---------------------------------------

CTX="$WORKDIR/context.txt"
PAYLOAD_FILE="$WORKDIR/payload.json"
RESP="$WORKDIR/resp.json"

# ----------------- obtain repo -----------------
REPO_DIR="$WORKDIR/repo"
if [[ -d "$REPO_SPEC/.git" || -f "$REPO_SPEC/.git" ]]; then
  # Local repo path
  echo "==> Using local repo: $REPO_SPEC"
  REPO_DIR="$(readlink -f "$REPO_SPEC")"
  cd "$REPO_DIR"
else
  # URL: shallow + sparse
  echo "==> Shallow sparse clone of: $REPO_SPEC"
  git clone --depth 1 --filter=blob:none --no-checkout "$REPO_SPEC" "$REPO_DIR" >/dev/null
  cd "$REPO_DIR"
  git sparse-checkout init --cone >/dev/null

  # Default sparse paths (good starting points for Accumulo)
  SPARSE_PATHS=(
    README.md
    core/src/main/java/org/apache/accumulo/core
    server
    shell
  )

  # If INCLUDE_PATHS provided, override sparse set
  if [[ -n "$INCLUDE_PATHS" ]]; then
    read -r -a SPARSE_PATHS <<< "$INCLUDE_PATHS"
  fi

  git sparse-checkout set "${SPARSE_PATHS[@]}" >/dev/null || true
  git checkout >/dev/null
fi
# -----------------------------------------------

echo "==> Selecting candidate files"
# Portable, case-insensitive keyword regex (no (?i))
KEYWORD_RE='(auth|authoriz|kerberos|token|password|secret|key|credential|encrypt|decrypt|cipher|jwt|tls|ssl|truststore|keystore|cert|x509|permission|visibility|acl|access|vulnerab|security|signature|mac|hmac|sha1|md5|nonce|salt)'

# Optionally narrow to INCLUDE_PATHS (works for local or cloned)
FIND_ROOTS=()
if [[ -n "$INCLUDE_PATHS" ]]; then
  # honor space-separated paths; fall back to repo root if any missing
  while read -r p; do
    [[ -n "$p" ]] || continue
    if [[ -d "$p" ]]; then FIND_ROOTS+=("$p"); fi
    if [[ -f "$p" ]]; then FIND_ROOTS+=("$p"); fi
  done < <(printf '%s\n' $INCLUDE_PATHS)
fi
if (( ${#FIND_ROOTS[@]} == 0 )); then
  FIND_ROOTS=(.)
fi

# Build ALLFILES with filters
mapfile -t ALLFILES < <(
  find "${FIND_ROOTS[@]}" -type f -readable \
    ! -path "*/.git/*" \
    ! -path "*/target/*" \
    ! -path "*/build/*" \
    ! -path "*/node_modules/*" \
    ! -path "*/dist/*" \
    ! -path "*/out/*" \
    ! -name "*.tgz" ! -name "*.tar.gz" ! -name "*.gz" \
    ! -name "*.zip" ! -name "*.jar" ! -name "*.war" ! -name "*.ear" \
    -size -200k \
    -print | LC_ALL=C sort
)

# Heuristic selection
CANDIDATES=()
for f in "${ALLFILES[@]}"; do
 [[ -r "$f" ]] || { echo "WARN: skipping unreadable $f"; continue; }  
  # skip binary-ish
  if file -b --mime "$f" | grep -qi 'charset=binary'; then
    continue
  fi
  # path hint or content hit
  if echo "$f" | grep -i -E -q "$KEYWORD_RE"; then
    CANDIDATES+=("$f")
    continue
  fi
  if grep -I -i -E -m1 "$KEYWORD_RE" "$f" >/dev/null 2>&1; then
    CANDIDATES+=("$f")
  fi
done

# include README.md if present
[[ -f README.md ]] && CANDIDATES=(README.md "${CANDIDATES[@]}")

# Dedupe, prioritize, cap to 40 files
CANDIDATES=($(printf '%s\n' "${CANDIDATES[@]}" \
  | awk '!seen[$0]++' \
  | awk '
    /\/security\// {print "0:"$0; next}
    /core\/src/    {print "1:"$0; next}
    /server\//     {print "1:"$0; next}
    /shell\//      {print "2:"$0; next}
    {print "3:"$0}
  ' \
  | sort -t: -k1,1 -k2,2 \
  | cut -d: -f2 \
  | head -n 40))

echo "Found ${#CANDIDATES[@]} candidate files"
if [[ ${#CANDIDATES[@]} -eq 0 ]]; then
  echo "No candidates matched; falling back to README.md if present."
  [[ -f README.md ]] && CANDIDATES=(README.md)
fi

echo "==> Packing context (caps: $MAX_TOTAL_BYTES total, $MAX_PER_FILE/file)"
: > "$CTX"
TOTAL=0
for p in "${CANDIDATES[@]}"; do
  [[ -f "$p" ]] || continue
  BYTES_LEFT=$((MAX_TOTAL_BYTES - TOTAL)); (( BYTES_LEFT <= 0 )) && break
  CAP=$MAX_PER_FILE; (( CAP > BYTES_LEFT )) && CAP=$BYTES_LEFT
  printf "\n===== PATH: %s =====\n" "${p#./}" >> "$CTX"
  head -c "$CAP" "$p" >> "$CTX" || true
  TOTAL=$(wc -c < "$CTX")
done
echo "Context bytes: $TOTAL"

# Split into chunks safely
mkdir -p "$WORKDIR/chunks"
split -b "$CHUNK_BYTES" -d -a 3 "$CTX" "$WORKDIR/chunk_" || true

shopt -s nullglob
CHUNK_FILES=( "$WORKDIR"/chunk_* )
shopt -u nullglob

# cap to MAX_CHUNKS
if (( ${#CHUNK_FILES[@]} > MAX_CHUNKS )); then
  CHUNK_FILES=( "${CHUNK_FILES[@]:0:MAX_CHUNKS}" )
fi
N=${#CHUNK_FILES[@]}
echo "Prepared $N chunk(s) from context"
if (( N == 0 )); then
  echo "ERROR: no chunks prepared (context too small or empty)."
  echo "Hint: raise MAX_TOTAL_BYTES / MAX_PER_FILE, or broaden INCLUDE_PATHS."
  exit 1
fi

# Build messages
TMPMSG="$WORKDIR/messages.jsonl"; :> "$TMPMSG"
jq -cn --arg focus "$FOCUS" '{
  role:"system",
  content: ("You are a seasoned application security engineer using a local model. "+
            "Work ONLY from the provided repository context chunks. "+
            "Goal: identify vulnerabilities related to: "+$focus+". "+
            "Return ONLY a JSON array: [{path,cwe_guess,severity,evidence,reasoning,fix,confidence}]. "+
            "If none, return [].")
}' >> "$TMPMSG"

i=1
for f in "${CHUNK_FILES[@]}"; do
  jq -cn --rawfile c "$f" --arg i "$i" --arg n "$N" '{
    role:"user",
    content: ("Context chunk ("+$i+"/"+$n+"): \n\n"+$c)
  }' >> "$TMPMSG"
  i=$((i+1))
done

jq -cn '{role:"user", content:"TASK: Produce ONLY a JSON array of findings. If none, return []"}' >> "$TMPMSG"

MESSAGES="$(jq -s '.' "$TMPMSG")"
jq -n --argjson messages "$MESSAGES" '{messages:$messages, stream:true}' > "$PAYLOAD_FILE"

# ---- call CRS with live logs and live stream ----
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

# Pretty-print (if valid JSON present)
echo "==> Parsed output (if valid JSON):"
pretty_print_response "$RESP"
