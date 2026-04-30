#!/bin/bash
set -euo pipefail

WORK=/home/osintd/dark_osint
PYTHON=/home/osintd/venv/bin/python
OUTBOX=/home/osint/outbox
CONFIG="$WORK/config"

cd "$WORK"

# Check for a day-specific queries file first, fall back to queries.txt
DAY=$(date +%A | tr '[:upper:]' '[:lower:]')
DAY_FILE="$CONFIG/queries_${DAY}.txt"
DEFAULT_FILE="$CONFIG/queries.txt"

if [ -f "$DAY_FILE" ]; then
    QUERY_FILE="$DAY_FILE"
    echo "Using day-specific queries: queries_${DAY}.txt"
else
    QUERY_FILE="$DEFAULT_FILE"
    echo "No queries_${DAY}.txt found, using queries.txt"
fi

if [ ! -f "$QUERY_FILE" ]; then
    echo "No query file found at $QUERY_FILE" >&2
    exit 1
fi

mapfile -t QUERIES < <(grep -v '^\s*#' "$QUERY_FILE" | grep -v '^\s*$')
if [ ${#QUERIES[@]} -eq 0 ]; then
    echo "No queries found in $QUERY_FILE" >&2
    exit 1
fi

echo "Running $(date) — ${#QUERIES[@]} queries from $(basename $QUERY_FILE)"
"$PYTHON" pipeline.py "${QUERIES[@]}" --pages 3
LATEST=$(ls -t "$WORK"/output/Mnemosyne_batch_*.json 2>/dev/null | head -1)
if [ -z "$LATEST" ]; then
    echo "No Mnemosyne batch output found" >&2
    exit 1
fi

BATCHES=$(ls -t "$WORK"/output/Mnemosyne_batch_*.json 2>/dev/null | head -5)
if [ -z "$BATCHES" ]; then
    echo "No Mnemosyne batch output found" >&2
    exit 1
fi

while IFS= read -r BATCH; do
    echo "Validating: $(basename "$BATCH")"
    "$PYTHON" validate_batch.py "$BATCH" --outbox "$OUTBOX"
done <<< "$BATCHES"