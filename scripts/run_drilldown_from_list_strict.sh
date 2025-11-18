#!/usr/bin/env bash
set -euo pipefail

LIST_FILE="${1:-$HOME/list.txt}"
OUTFILE="${2:-$HOME/drilldown_findings_from_list.jsonl}"
PROMPT="${3:-hard-coded secrets, weak crypto, auth & input validation}"

# ensure runner present
test -x "$HOME/crs_drilldown_file_min.sh" || chmod +x "$HOME/crs_drilldown_file_min.sh"

# normalize list endings
TMP_LIST="$(mktemp)"; sed 's/\r$//' "$LIST_FILE" > "$TMP_LIST"

# outputs
: > "$OUTFILE"
ARTDIR="$OUTFILE.artifacts"
mkdir -p "$ARTDIR"
MISS="$OUTFILE.missing_or_unreadable.txt"; : > "$MISS"
FAIL="$OUTFILE.failures.log"; : > "$FAIL"

echo "==> List: $LIST_FILE"
echo "==> Out : $OUTFILE"
echo "==> Art : $ARTDIR"
echo "==> Prompt: $PROMPT"

scanned=0
found=0

while IFS= read -r RAWPATH; do
  [[ -z "$RAWPATH" || "${RAWPATH:0:1}" == "#" ]] && continue
  FILE="$(printf '%s' "$RAWPATH" | awk '{$1=$1;print}')"
  [[ "$FILE" == ~* ]] && FILE="${FILE/#\~/$HOME}"

  if [[ ! -e "$FILE" ]]; then
    echo "WARN: No such file: $FILE" | tee -a "$MISS" >&2
    continue
  fi
  if [[ ! -f "$FILE" ]]; then
    echo "WARN: Not a regular file: $FILE" | tee -a "$MISS" >&2
    continue
  fi
  if [[ ! -r "$FILE" ]]; then
    echo "WARN: Permission denied: $FILE" | tee -a "$MISS" >&2
    continue
  fi

  scanned=$((scanned+1))
  b64="$(printf '%s' "$FILE" | base64 -w 0)"
  pf="$ARTDIR/$b64"
  RAW="$pf.raw.txt"
  JSONL="$pf.jsonl"

  echo "==> Scanning: $FILE"
  # Run the drilldown; capture raw mixed output
  set +e
  "$HOME/crs_drilldown_file_min.sh" "$FILE" "$PROMPT" \
     >"$RAW" 2>>"$FAIL"
  rc=$?
  set -e

  # Try to extract JSON objects from raw (robust even with prose/stream)
  # This Python extracts the largest valid JSON object substrings and prints each on its own line.
  python3 - "$RAW" "$JSONL" <<'PY'
import sys, json, re
raw_path, out_path = sys.argv[1], sys.argv[2]
raw = open(raw_path, 'r', errors='replace').read()

# Find candidate JSON blocks that look like objects
cands = []
stack = 0
start = None
for i,ch in enumerate(raw):
    if ch == '{':
        if stack == 0:
            start = i
        stack += 1
    elif ch == '}':
        if stack > 0:
            stack -= 1
            if stack == 0 and start is not None:
                cands.append(raw[start:i+1])

valid = []
for c in cands:
    try:
        obj = json.loads(c)
        # Heuristic: must have at least path or findings/cwe to be a “finding”
        if isinstance(obj, dict) and any(k in obj for k in ('path','cwe','cwe_guess','findings')):
            valid.append(obj)
        elif isinstance(obj, list):
            # flatten a list of findings objects
            for it in obj:
                if isinstance(it, dict) and any(k in it for k in ('path','cwe','cwe_guess')):
                    valid.append(it)
    except Exception:
        pass

if valid:
    with open(out_path, 'w') as f:
        for v in valid:
            f.write(json.dumps(v, ensure_ascii=False) + "\n")
    print(f"[extractor] extracted {len(valid)} finding object(s) → {out_path}")
else:
    print("[extractor] no valid JSON objects found")
PY

  if [[ -s "$JSONL" ]]; then
    cat "$JSONL" >> "$OUTFILE"
    cnt="$(wc -l < "$JSONL" | tr -d ' ')"
    found=$((found+cnt))
  else
    echo "WARN: No JSON findings extracted for $FILE" | tee -a "$FAIL" >&2
  fi

  # Optional: short throttle to avoid hammering service
  sleep 0.1
done < "$TMP_LIST"

rm -f "$TMP_LIST"

echo "==> Done. Scanned: $scanned ; Extracted findings: $found"
echo "==> Findings JSONL: $OUTFILE"
echo "==> Artifacts per-file: $ARTDIR"
echo "==> Missing/perm: $MISS (if non-empty)"
echo "==> Failures:     $FAIL (if non-empty)"
