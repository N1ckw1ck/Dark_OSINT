#!/bin/bash

# HELPER SCRIPT -- NEEDS MODIFICATION TO WORK PROPERLY
# Edit line with ADDME comment (manually edit date range)

OUTPUT_DIR="/home/osintd/dark_osint/output/mnemosyne"
HOME_DIR="/home/osintd/dark_osint"
PYTHON="/home/osintd/venv/bin/python"
OUTBOX_DIR="/home/osint/outbox" # Place to put the validated files


# edit date ranges in {}                          these ones ADDME
for file in "$OUTPUT_DIR"/Mnemosyne_batch_202608{01,02,03,04,05}_*.json; do
    "$PYTHON" "$HOME_DIR/validate_batch.py" "$file" --outbox "$OUTBOX_DIR" || echo "[WARN] failed for $file (exit $?)"
done