#!/bin/bash
set -euo pipefail

WORK=/home/osintd/dark_osint
PYTHON=/home/osintd/venv/bin/python
CONFIG="$WORK/config"

cd "$WORK"

# Day specific queries
DAY=$(date +%A | tr '[:upper:]' '[:lower:]')
DAY_FILE="$CONFIG/queries_${DAY}.txt"
DEFAULT_FILE="$CONFIG/queries.txt"

echo "Pipeline starting at $(date)" >> /home/osintd/dark_osint/pipeline.log
if [ -f "$DAY_FILE" ]; then
    QUERY_FILE="$DAY_FILE"
    echo "Using day-specific queries: queries_${DAY}.txt"
else
    QUERY_FILE="$DEFAULT_FILE"
    echo "No queries_${DAY}.txt found, using queries.txt"
fi

if [ ! -f "$QUERY_FILE" ]; then
    echo "No query file found att $QUERY_FILE" >&2
    exit 1
fi

# Run pipeline with queries from file
mapfile -t QUERIES < <(grep -v '^\s*#' "$QUERY_FILE" | grep -v '^\s*$')

if [ ${#QUERIES[@]} -eq 0 ]; then
    echo "No queries found in $QUERY_FILE" >&2
    exit 1
fi

echo "Running $(date) - ${QUERIES[@]} queries from $(basename $QUERY_FILE)"
"$PYTHON" pipeline.py "${QUERIES[@]}" --pages 10 --no-khaeos

# Change head for how many lines are in each query file
BATCHES=$(ls -t "$WORK"/output/Mnemosyne_batch_*.json 2>/dev/null | head -6)

if [ -z "$BATCHES" ]; then
    echo "No Mnemosyne batch output found" >&2
    exit 1
fi
while IFS= read -r BATCH; do
    echo "Validating: $(basename $BATCH)"
    "$PYTHON" validate_batch.py "$BATCH" --outbox /home/osint/outbox
echo "Done - $(date)"
done <<< "$BATCHES"