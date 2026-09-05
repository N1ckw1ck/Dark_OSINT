#!/bin/bash

# HELPER SCRIPT -- NEEDS MODIFICATION TO WORK
# Edit lines with ADDME comment

set -e

DARK_OSINT_DIR="/path/to/Dark_OSINT" # path to root of this repo ADDME
PYTHON="$DARK_OSINT_DIR/venv/bin/python"
KHAEOS_ENGINE="$DARK_OSINT_DIR/Khaeos/d_khaeos.py"
BATCH_DIR="$DARK_OSINT_DIR/Khaeos/batches_for_ingestion"

if [ ! -d "$DARK_OSINT_DIR" ]; then
    echo "Directory not found at $DARK_OSINT_DIR"
    exit 1
fi


# Manually edit the date ranges in {}           these ones ADDME
for file in "$BATCH_DIR"/Mnemosyne_batch_202606{01,02,03,04}_*.json; do
    "$PYTHON" "$KHAEOS_ENGINE" --ingest "$file"
done