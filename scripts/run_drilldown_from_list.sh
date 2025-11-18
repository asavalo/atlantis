#!/usr/bin/env bash
set -euo pipefail

LIST_FILE="${1:-$HOME/list.txt}"
OUTFILE="${2:-$HOME/drilldown_findings_from_list.jsonl}"
PROMPT="${3:-hard-coded secrets, weak crypto, auth & input validation}"

# Normalize list file endings (CRLF -> LF) into a temp copy
TMP_LIST="$(mktemp)"
sed 's/\r$//' "$LIST_FILE" > "$TMP_LIST"

# Prepare outputs
: > "$OUTFILE"
MISSING="$OUTFILE.missing_paths.txt"
: > "$MISSING"
FAIL_LOG="$OUTFILE.failures.log"
: > "$FAIL_LOG"

echo "==> Reading list: $LIST_FILE"
echo "==> Writing findings to: $OUTFILE"
echo "==> Failures to: $FAIL_LOG"
echo "==> Missing paths to: $MISSING"
echo "==> Prompt: $PROMPT"

# Count scanned files
scanned=0
found=0

while IFS= read -r RAW; do
  # Skip empty or commented lines
  [[ -z "$RAW" || "${RAW:0:1}" == "#" ]] && continue

  # Trim trailing CR (already handled by sed), trim surrounding whitespace
  FILE="$(printf '%s' "$RAW" | awk '{$1=$1;print}')"

  # Expand ~ manually if present
  if [[ "$FILE" == ~* ]]; then
    FILE="${FILE/#\~/$HOME}"
  fi

  if [[ ! -f "$FILE" ]]; then
    echo "WARN: No such file: $FILE" | tee -a "$MISSING" >&2
    continue
  fi

  echo "==> Scanning: $FILE"
  # Run the minimal drilldown; append both stdout and stderr to a per-file log, keep stdout in OUTFILE
  # We capture exit code from the script while still appending to OUTFILE.
  RUN_LOG="$(mktemp)"
  if ~/crs_drilldown_file_min.sh "$FILE" "$PROMPT" 2> >(tee -a "$FAIL_LOG" >&2) | tee -a "$OUTFILE" > "$RUN_LOG"; then
    scanned=$((scanned+1))
    # Heuristic: count a line that looks like JSON object start to increment 'found'
    if grep -q '^{.*}' "$RUN_LOG"; then
      found=$((found+1))
    fi
  else
    echo "ERROR: scan failed for $FILE" | tee -a "$FAIL_LOG" >&2
  fi
  rm -f "$RUN_LOG"
done < "$TMP_LIST"

rm -f "$TMP_LIST"

echo "==> Done. Scanned files: $scanned; Findings (heuristic): $found"
echo "==> Findings JSONL: $OUTFILE"
echo "==> Missing paths: $MISSING (if non-empty)"
echo "==> Failures log:  $FAIL_LOG (if non-empty)"
