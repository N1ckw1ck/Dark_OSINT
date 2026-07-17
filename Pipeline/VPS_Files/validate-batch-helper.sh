#!/bin/bash

# Hardcoded day helper
OUTPUT_DIR="/home/osintd/dark_osint/output"

for file in "$OUTPUT_DIR"/Mnemosyne_batch_202606{15,16,17,18,19,20,21,23,24,25,26,27,29,30}_*.json; do
    python validate_batch.py "$file" --outbox /home/osint/outbox
done