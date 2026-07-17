#!/bin/bash
set -uo pipefail

WORK=/home/osintd/dark_osint
PYTHON=/home/osintd/venv/bin/python
OUTBOX=/home/osint/outbox
CONFIG="$WORK/config"
MNEMOSYNE_OUT="$WORK/output/mnemosyne"
DISCOVERY_QUEUE="$WORK/output/discovery_queue.txt"

cd "$WORK" || exit 1
mkdir -p "$MNEMOSYNE_OUT"

echo "Pipeline starting at $(date)"

# Day specific queries
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

# Marker file pick up every batch produced by THIS run below not last N
MARKER=$(mktemp)

# Consume any links --aggressive queued up on a PREVIOUS run before adding more to the queue below.
if [ -s "$DISCOVERY_QUEUE" ]; then
        QUEUED_COUNT=$(grep -vc '^\s*#\|^\s*$' "$DISCOVERY_QUEUE" || true)
        echo "Scanning discovery queue from a previous run (${QUEUED_COUNT} URLs)..."
        DISCOVERY_TMP="$WORK/output/discovery_queue.$(date +%s).txt"
        mv "$DISCOVERY_QUEUE" "$DISCOVERY_TMP"
        ( cd "$MNEMOSYNE_OUT" && "$PYTHON" "$WORK/d_mnemosyne.py" --batch "$DISCOVERY_TMP" --save )
        rm -f "$DISCOVERY_TMP"
fi

echo "Running $(date) - ${QUERIES[*]} queries from $(basename "$QUERY_FILE")"
"$PYTHON" pipeline.py "${QUERIES[@]}" --pages 10 --no-khaeos --aggressive
PIPELINE_RC=$?
if [ "$PIPELINE_RC" -ne 0 ]; then
        echo "pipeline.py reported one or more failed queries (exit $PIPELINE_RC) — validating whatever batches did complete."
fi

mapfile -t BATCHES < <(find "$MNEMOSYNE_OUT" -name 'Mnemosyne_batch_*.json' -newer "$MARKER" 2>/dev/null | sort)
rm -f "$MARKER"

if [ ${#BATCHES[@]} -eq 0 ]; then
        echo "No new Mnemosyne batch output found this run" >&2
        exit 1
fi

for BATCH in "${BATCHES[@]}"; do
        echo "Validating: $(basename "$BATCH")"
        "$PYTHON" validate_batch.py "$BATCH" --outbox "$OUTBOX"
done

echo "Done - $(date)"