#!/usr/bin/env bash
# Run the strict single-file CWE runner across a repo, then merge results.
#
# Requirements:
#   - ~/crs_single_file_cwe_strict.sh (the strict single-file runner you used)
#
# Usage:
#   SHOW_LOGS=1 INCLUDE_PATHS="path1 path2" EXCLUDE_PATHS=".git target build" \
#   FILE_GLOBS="*.java *.xml *.properties *.conf *.sh" TOP_N=400 CONCURRENCY=2 \
#   LLM_MAX_TOKENS=900 LLM_TEMPERATURE=0 TIMEOUT=900 \
#   ./crs_repo_via_singlefile.sh <repo_dir> "<focus prompt>" <out.json>
#
# Example:
#   SHOW_LOGS=1 INCLUDE_PATHS="server/base/src/main/java core/src/main/java" \
#   ./crs_repo_via_singlefile.sh ~/accumulo \
#     "hard-coded secrets, weak crypto (MD5/SHA1), impersonation/ACL issues" \
#     ~/accumulo_full_repo.json

set -Eeuo pipefail

REPO="${1:-}"; FOCUS="${2:-security vulnerabilities}"; OUT="${3:-repo_findings.json}"
[[ -d "${REPO:-}" ]] || { echo "ERROR: repo not found: $REPO" >&2; exit 2; }
[[ -x "$HOME/crs_single_file_cwe_strict.sh" ]] || { echo "ERROR: ~/crs_single_file_cwe_strict.sh not found or not executable" >&2; exit 3; }

# Tunables (caller can override via env)
: "${ENDPOINT:=http://127.0.0.1:8000/v1/crs/run}"
: "${LLM_MAX_TOKENS:=900}"
: "${LLM_TEMPERATURE:=0}"
: "${TIMEOUT:=900}"

: "${INCLUDE_PATHS:=}"  # e.g. "server/base/src/main/java core/src/main/java"
: "${EXCLUDE_PATHS:=.git target build dist out node_modules .mvn .github}"  # space-separated
: "${FILE_GLOBS:=*.java *.xml *.properties *.conf *.sh *.yaml *.yml pom.xml *.gradle}"
: "${MAX_PER_FILE:=25000}"   # skip files bigger than this (bytes)
: "${TOP_N:=400}"            # max files to scan (keeps runtime bounded)
: "${CONCURRENCY:=2}"        # parallel workers (2 is safe; increase if CPU allows)
: "${SHOW_LOGS:=0}"          # 1 -> follow docker logs while running

# Optional live logs from containers
if [[ "$SHOW_LOGS" == "1" ]]; then
  { docker compose logs -f --tail=0 atlantis-webservice & echo $! > /tmp/.crs_repo_logs.pids; } 2>/dev/null || true
  { docker compose logs -f --tail=0 ollama & echo $! >> /tmp/.crs_repo_logs.pids; } 2>/dev/null || true
  trap '[[ -f /tmp/.crs_repo_logs.pids ]] && while read -r p; do kill "$p" 2>/dev/null || true; done < /tmp/.crs_repo_logs.pids' EXIT
fi

WORK="$(mktemp -d)"
LOG="$WORK/run.log"
JSONL="$WORK/all.jsonl"
: > "$JSONL"

echo "WORKDIR: $WORK" | tee -a "$LOG"
echo "Repo: $REPO" | tee -a "$LOG"
echo "Focus: $FOCUS" | tee -a "$LOG"

cd "$REPO"

# Build exclude expression for find
exclude_expr=()
for e in $EXCLUDE_PATHS; do exclude_expr+=( -not -path "*/$e/*" ); done

# Gather files
if [[ -n "$INCLUDE_PATHS" ]]; then
  mapfile -t ALLFILES < <(
    for root in $INCLUDE_PATHS; do
      for g in $FILE_GLOBS; do
        find "$root" -type f -readable "${exclude_expr[@]}" -name "$g" \
          -size -"${MAX_PER_FILE}"c -print 2>/dev/null || true
      done
    done | LC_ALL=C sort -u
  )
else
  mapfile -t ALLFILES < <(
    for g in $FILE_GLOBS; do
      find . -type f -readable "${exclude_expr[@]}" -name "$g" \
        -size -"${MAX_PER_FILE}"c -print 2>/dev/null || true
    done | LC_ALL=C sort -u
  )
fi
echo "==> Files considered: ${#ALLFILES[@]}" | tee -a "$LOG"

# Lightweight keyword prefilter to prioritize likely security files
KW='(auth|authoriz|impersonat|kerberos|sasl|token|password|secret|key|credential|encrypt|decrypt|cipher|jwt|tls|ssl|truststore|keystore|cert|x509|permission|visibility|acl|access|vulnerab|security|signature|mac|hmac|sha1|md5|nonce|salt)'

CAND=()
for f in "${ALLFILES[@]}"; do
  [[ -r "$f" ]] || continue
  # skip binaries
  file -b --mime "$f" 2>/dev/null | grep -qi 'charset=binary' && continue || true
  # prefer files with keywords
  if grep -I -i -E -m1 "$KW" -- "$f" >/dev/null 2>&1; then
    CAND+=("$f")
  fi
done

# If no keyword hits, fall back to first TOP_N
if (( ${#CAND[@]} == 0 )); then
  CAND=("${ALLFILES[@]:0:$TOP_N}")
else
  # cap list to TOP_N (keep stable order)
  if (( ${#CAND[@]} > TOP_N )); then
    CAND=("${CAND[@]:0:$TOP_N}")
  fi
fi

echo "==> Candidate files: ${#CAND[@]} (TOP_N=$TOP_N)" | tee -a "$LOG"

# Build a worklist file
LIST="$WORK/files.txt"
printf '%s\n' "${CAND[@]}" > "$LIST"

# Function to run single-file strict scanner on one file
run_one() {
  local f="$1"
  local outf
  outf="$(mktemp -p "$WORK" out_XXXX.json)"
  # Call your strict single-file runner EXACTLY as-is
  ENDPOINT="$ENDPOINT" \
  LLM_MAX_TOKENS="$LLM_MAX_TOKENS" \
  LLM_TEMPERATURE="$LLM_TEMPERATURE" \
  TIMEOUT="$TIMEOUT" \
  "$HOME/crs_single_file_cwe_strict.sh" "$f" "$outf" >/dev/null 2>&1 || true
  # Append items (if any) to JSONL
  jq -c '.[]?' "$outf" 2>/dev/null >> "$JSONL" || true
  echo "$f -> $outf" >> "$WORK/per-file.log"
}

export -f run_one
export WORK JSONL ENDPOINT LLM_MAX_TOKENS LLM_TEMPERATURE TIMEOUT
export -f run_one

# Run sequentially or with simple parallelism (xargs)
if command -v xargs >/dev/null 2>&1; then
  < "$LIST" xargs -I {} -P "$CONCURRENCY" bash -c 'run_one "$@"' _ {}
else
  while read -r f; do run_one "$f"; done < "$LIST"
fi

# Merge & de-dup
python3 - "$JSONL" > "$OUT" <<'PY'
import sys, json, hashlib
items=[]
for line in open(sys.argv[1],'r',errors='ignore'):
  line=line.strip()
  if not line: continue
  try:
    it=json.loads(line)
    # keep only strict-shape objects (same schema as single-file script)
    req={"path","cwe_guess","severity","confidence","lines","snippet","evidence","reasoning","fix"}
    if isinstance(it,dict) and req.issubset(it.keys()):
      items.append(it)
  except: pass

def key(it):
  sn=(it.get('snippet') or '')[:200]
  lines=tuple(it.get('lines') or [])
  return (it.get('path',''), lines, it.get('cwe_guess',''),
          hashlib.md5(sn.encode('utf-8','ignore')).hexdigest()[:8])

uniq={}
for it in items:
  uniq[key(it)] = it

out = sorted(uniq.values(), key=lambda x: float(x.get('confidence',0.0)), reverse=True)
print(json.dumps(out, indent=2))
PY

jq -r 'length as $n | "findings=\($n)"' "$OUT" 2>/dev/null || true
echo "WROTE $OUT"
echo "WORKDIR $WORK (logs & intermediates)"
