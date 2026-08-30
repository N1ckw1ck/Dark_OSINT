#!/bin/bash

set -e

DARK_OSINT_DIR=/path/to/Dark_OSINT
YOUR_VPS_IP=ADDME
SSH_KEY_PATH=/path/to/.ssh/key # typically ~/.ssh/vps_dark_suite

cd "$DARK_OSINT_DIR"

if [ ! -d "$DARK_OSINT_DIR" ]; then
    echo "Directory not found at: $DARK_OSINT_DIR"
    exit 1
fi

./venv/bin/python Pipeline/Local_Machine_Files/pull_batches.py --vps-ip "$YOUR_VPS_IP" --key "$SSH_KEY_PATH" --local-dir "$DARK_OSINT_DIR/Khaeos/batches_for_ingestion" --khaeos-db "$DARK_OSINT_DIR/Khaeos/khaeos.db"