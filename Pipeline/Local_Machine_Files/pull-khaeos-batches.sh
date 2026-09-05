#!/bin/bash

# HELPER SCRIPT -- NEEDS MODIFICATION TO WORK
# Edit lines with ADDME comment

set -e

DARK_OSINT_DIR=/path/to/Dark_OSINT # path to root of this repo ADDME
YOUR_VPS_IP=ADDME
SSH_KEY_PATH=/path/to/.ssh/key # default ~/.ssh/vps_dark_suite ADDME

PYTHON="$DARK_OSINT_DIR/venv/bin/python"
PULL_BATCHES="$DARK_OSINT_DIR/Pipeline/Local_Machine_Files/pull_batches.py"
BATCH_DIR="$DARK_OSINT_DIR/Khaeos/batches_for_ingestion"
KHAEOS_DB="$DARK_OSINT_DIR/Khaeos/khaeos.db"

if [ ! -d "$DARK_OSINT_DIR" ]; then
    echo "Directory not found at: $DARK_OSINT_DIR"
    exit 1
fi

"$PYTHON" "$PULL_BATCHES" --vps-ip "$YOUR_VPS_IP" --key "$SSH_KEY_PATH" --local-dir "$BATCH_DIR" --khaeos-db "$KHAEOS_DB"