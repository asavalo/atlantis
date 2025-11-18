#!/bin/bash

# Set variables
REPO_DIR=$1                   # Ghidra repository path (e.g., ~/ghidra)
OUTPUT_FILE=$2                # Output file path (e.g., ~/ghidra_findings.jsonl)
BATCH_SIZE=${3:-50}           # Default to 50 files per batch if not provided

# Ensure output directory exists
mkdir -p "$(dirname "$OUTPUT_FILE")"

# Define file extensions to scan (.java, .c, .h)
FILE_EXTENSIONS="\.java|\.c|\.h"

# Build file list (Java, C, H files)
echo "Building file list for Java, C, H files..."
FILES=$(find "$REPO_DIR" -type f -regex ".*\($FILE_EXTENSIONS\)$")

# Check the number of files found
echo "Files to scan: $(echo "$FILES" | wc -l)"

# Initialize variables for workers and other setup
WORKERS=4
PORT_OFFSET=0
RETRIES=2

# Define health check for webservice
HEALTH_CHECK_URL="http://127.0.0.1:8000/healthz"

# Start workers and check health
echo "Checking webservice health..."
curl -sf $HEALTH_CHECK_URL || { echo "Webservice not healthy, exiting..."; exit 1; }

# Start scanning process for files (streaming results to JSONL)
echo "Starting scan for files..."

for FILE in $FILES; do
    echo "Processing file: $FILE"
    
    # Retry logic for failed files (500 errors, timeouts)
    attempt=1
    while [[ $attempt -le $RETRIES ]]; do
        response=$(curl -s -w "%{http_code}" -o /tmp/tmp_response.json \
            -X POST "http://127.0.0.1:8000/v1/crs/run" -H "Content-Type: application/json" \
            -d '{"file_path": "'"$FILE"'", "scan_type": "multilang"}')
        
        if [[ "$response" == "200" ]]; then
            # Append results to JSONL output file
            cat /tmp/tmp_response.json >> "$OUTPUT_FILE"
            break
        else
            echo "Failed to process $FILE (attempt $attempt). HTTP $response."
            if [[ $attempt -eq $RETRIES ]]; then
                echo "Giving up on $FILE after $RETRIES attempts."
                break
            fi
            attempt=$((attempt + 1))
        fi
    done

    # Optional: Monitor progress
    echo "Processed: $FILE"
done

echo "Scan completed. Findings saved to $OUTPUT_FILE"
