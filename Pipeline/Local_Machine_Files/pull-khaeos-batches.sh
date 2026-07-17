#!/bin/bash

set -e

DARK_OSINT_DIR=/path/to/Dark_OSINT

cd "$DARK_OSINT_DIR"

if [ ! -d "$DARK_OSINT_DIR" ]; then
    echo "Directory not found at: $DARK_OSINT_DIR"
    exit 1
fi

./venv/bin/python pull_batches.py --vps-ip YOUR.VPS.IP --local-dir "$DARK_OSINT_DIR/Khaeos/batches_for_ingestion" --no-ingest