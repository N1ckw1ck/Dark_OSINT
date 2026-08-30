#!/bin/bash

# Hardcoded day helper, manually edit date range


OUTPUT_DIR="/home/osintd/dark_osint/output/mnemosyne"
HOME_DIR="/home/osintd/dark_osint"
PYTHON="/home/osintd/venv/bin/python"
# Place to put the validated files
OUTBOX_DIR="/home/osint/outbox"


for file in "$OUTPUT_DIR"/Mnemosyne_batch_202608{15,16,17,18,19,20,21,23,24,25,26,27,29,30}_*.json; do
    "$PYTHON" "$HOME_DIR/validate_batch.py" "$file" --outbox "$OUTBOX_DIR" || echo "[WARN] failed for $file (exit $?)"
done