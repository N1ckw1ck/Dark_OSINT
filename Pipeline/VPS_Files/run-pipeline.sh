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

echo "Running $(date) - ${QUERIES[*]} queries from $(basename "$QUERY_FILE")"
"$PYTHON" pipeline.py "${QUERIES[@]}" --pages 10 --no-khaeos --aggressive --outbox "$OUTBOX"
PIPELINE_RC=$?
if [ "$PIPELINE_RC" -ne 0 ]; then
        echo "pipeline.py reported one or more failed queries (exit $PIPELINE_RC)."
fi

echo "Primary queries finished at $(date)"

# Consume links --aggressive queued up
if [ -s "$DISCOVERY_QUEUE" ]; then
        NEXT_RUN_EPOCH=$(date -d "tomorrow 02:00" +%s)
        NOW_EPOCH=$(date +%s)
        SAFETY_MARGIN_SECONDS=1800
        SECONDS_PER_URL=30
        USABLE_SECONDS=$(( NEXT_RUN_EPOCH - NOW_EPOCH - SAFETY_MARGIN_SECONDS ))

        if [ "$USABLE_SECONDS" -gt 0 ]; then
                URL_BUDGET=$(( USABLE_SECONDS / SECONDS_PER_URL ))
        else
                URL_BUDGET=0
        fi

        QUEUED_COUNT=$(grep -vc '^\s*#\|^\s*$' "$DISCOVERY_QUEUE" || true)

        if [ "$URL_BUDGET" -gt 0 ]; then
                echo "Discovery queue has ${QUEUED_COUNT} URL(s); ~$((USABLE_SECONDS/60)) min left before next run, scanning up to ${URL_BUDGET}."
                DISCOVERY_TMP="$WORK/output/discovery_queue.$(date +%s).txt"
                head -n "$URL_BUDGET" "$DISCOVERY_QUEUE" > "$DISCOVERY_TMP"
                tail -n "+$((URL_BUDGET + 1))" "$DISCOVERY_QUEUE" > "$DISCOVERY_QUEUE.remaining"
                mv "$DISCOVERY_QUEUE.remaining" "$DISCOVERY_QUEUE"

                DISCOVERY_MARKER=$(mktemp)
                ( cd "$MNEMOSYNE_OUT" && "$PYTHON" "$WORK/d_mnemosyne.py" --batch "$DISCOVERY_TMP" --save )
                rm -f "$DISCOVERY_TMP"

                DISCOVERY_BATCH=$(find "$MNEMOSYNE_OUT" -name 'Mnemosyne_batch_*.json' -newer "$DISCOVERY_MARKER" | sort | tail -n 1)
                rm -f "$DISCOVERY_MARKER"

                if [ -n "$DISCOVERY_BATCH" ]; then
                        echo "Validating discovery batch: $(basename "$DISCOVERY_BATCH")"
                        "$PYTHON" validate_batch.py "$DISCOVERY_BATCH" --outbox "$OUTBOX"
                else
                        echo "No discovery batch output found" >&2
                fi

        else
                echo "No time left before the next run - leaving ${QUEUED_COUNT} URL(s) queued."
        fi
fi

echo "Done - $(date)"