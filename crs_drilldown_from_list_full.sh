#!/usr/bin/env bash
LIST_FILE="${1:-~/list.txt}"
OUTFILE="${2:-~/drilldown_findings_from_list.jsonl}"
PROMPT="${3:-hard-coded secrets, weak crypto, auth & input validation}"

echo "==> Starting CRS drilldown from list: $LIST_FILE"
> "$OUTFILE"

while read -r file; do
  [[ -z "$file" ]] && continue
  echo "==> Scanning $file"
  ~/crs_drilldown_file_min.sh "$file" "$PROMPT" \
    | tee -a "$OUTFILE"
done < "$LIST_FILE"

echo "==> Drilldown complete. Results written to $OUTFILE"
