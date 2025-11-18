#!/usr/bin/env bash
set -euo pipefail

LIST_FILE="${1:-$HOME/list.txt}"
REPO_ROOT="${2:-$HOME/ghidra}"                   # used only for pretty relative paths
OUT_ROOT="${3:-$HOME/ghidra_findings}"           # all outputs here
PROMPT="${4:-hard-coded secrets, weak crypto, auth & input validation}"

# Ensure runner exists
test -x "$HOME/crs_drilldown_file_min.sh" || chmod +x "$HOME/crs_drilldown_file_min.sh"

# Normalize CRLF -> LF to a temp copy
TMP_LIST="$(mktemp)"
sed 's/\r$//' "$LIST_FILE" > "$TMP_LIST"

# Prepare dirs
mkdir -p "$OUT_ROOT"
COMBINED="$OUT_ROOT/_combined.jsonl"
: > "$COMBINED"

echo "==> List:      $LIST_FILE"
echo "==> Repo root: $REPO_ROOT"
echo "==> Out root:  $OUT_ROOT"
echo "==> Prompt:    $PROMPT"

# Helper: make a safe filename for non-repo files
safe_b64() { printf '%s' "$1" | base64 -w 0 | tr -d '='; }

scanned=0
found=0

while IFS= read -r RAWPATH; do
  [[ -z "$RAWPATH" || "${RAWPATH:0:1}" == "#" ]] && continue
  FILE="$(printf '%s' "$RAWPATH" | awk '{$1=$1;print}')"
  [[ "$FILE" == ~* ]] && FILE="${FILE/#\~/$HOME}"

  if [[ ! -f "$FILE" || ! -r "$FILE" ]]; then
    echo "WARN: skip (missing/unreadable): $FILE" >&2
    continue
  fi

  scanned=$((scanned+1))

  # Derive per-file output path
  if [[ "$FILE" == "$REPO_ROOT/"* ]]; then
    REL="${FILE#${REPO_ROOT}/}"                    # path relative to repo
    OUT_DIR="$OUT_ROOT/$(dirname "$REL")"
    OUT_BASE="$(basename "$REL")"
    mkdir -p "$OUT_DIR"
    PF="$OUT_DIR/${OUT_BASE}"                      # base path for artifacts
  else
    mkdir -p "$OUT_ROOT/_external"
    PF="$OUT_ROOT/_external/$(safe_b64 "$FILE")"   # base64 if outside repo
  fi

  RAW="$PF.raw.txt"
  ERR="$PF.err.log"
  OUT="$PF.jsonl"

  echo "==> Scanning: $FILE"
  # Run minimal drilldown; capture raw+err per-file
  set +e
  "$HOME/crs_drilldown_file_min.sh" "$FILE" "$PROMPT" >"$RAW" 2>>"$ERR"
  rc=$?
  set -e

  # Extract JSON objects from raw (robust to prose/stream); append to per-file OUT and _combined
  python3 - "$RAW" "$OUT" <<'PY'
import sys, json
raw_path, out_path = sys.argv[1], sys.argv[2]
raw = open(raw_path, 'r', errors='replace').read()

# Collect balanced {...} candidates
objs, stack, start = [], 0, None
for i,ch in enumerate(raw):
    if ch == '{':
        if stack == 0: start = i
        stack += 1
    elif ch == '}':
        if stack > 0:
            stack -= 1
            if stack == 0 and start is not None:
                objs.append(raw[start:i+1])

valid = []
for s in objs:
    try:
        j = json.loads(s)
        if isinstance(j, dict):
            # single finding or container with 'findings'
            if 'findings' in j and isinstance(j['findings'], list):
                valid.extend([f for f in j['findings'] if isinstance(f, dict)])
            else:
                valid.append(j)
        elif isinstance(j, list):
            valid.extend([f for f in j if isinstance(f, dict)])
    except Exception:
        pass

if valid:
    with open(out_path, 'w') as f:
        for v in valid:
            f.write(json.dumps(v, ensure_ascii=False) + "\n")
    print(f"[ok] {len(valid)} finding(s) -> {out_path}")
else:
    print("[ok] 0 findings")
PY

  if [[ -s "$OUT" ]]; then
    cat "$OUT" >> "$COMBINED"
    n=$(wc -l < "$OUT" | tr -d ' ')
    found=$((found+n))
  fi

  # Tiny pause to avoid hammering service
  sleep 0.05
done < "$TMP_LIST"

rm -f "$TMP_LIST"

echo "==> Done. Files scanned: $scanned ; Findings total: $found"
echo "==> Combined JSONL: $COMBINED"
echo "==> Per-file outputs live under: $OUT_ROOT"
