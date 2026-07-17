#!/bin/bash

# Fallback working version, must have activated venv, replace days in format {DD,DD,DD}

#BATCH_DIR="batches_for_ingestion"

#for file in "$BATCH_DIR"/Mnemosyne_batch_202606{15,16,17,18,19,20,21,23,24,25,26,27,28,29,30}_*.json; do
    #python d_khaeos.py --ingest "$file"
#done


#Intended update (TESTING)
VENV_DIR="/path/to/Dark_OSINT/venv"
BATCH_DIR="/path/to/Dark_OSINT/Khaeos/batches_for_ingestion"

if [ -d "$VENV_DIR" ]; then
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"

    if [ -n "$VIRTUAL_ENV" ]; then
        echo "VENV activated successfully"
        else
            echo "Error: Failed to activated VENV"
            exit 1

    fi

fi

for file in "$BATCH_DIR"/Mnemosyne_batch_202606{}_*.json; do
    python d_khaeos.py --ingest "$file"
done