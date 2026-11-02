#!/usr/bin/env bash
# NetWatch SOC — Full Automated Pipeline Execution Script
# Usage: ./scripts/run_pipeline.sh [path_to_pcap]

set -e

PCAP_PATH="$1"

if [ -n "$PCAP_PATH" ]; then
    echo "1. Processing PCAP file '${PCAP_PATH}' with Zeek..."
    ZEEK_DIR=$(./scripts/process_pcap.sh "$PCAP_PATH" | tail -n 1)
    
    echo "2. Running ETL & Detection Engine on generated Zeek logs..."
    python scripts/run_pipeline.py --zeek-dir "$ZEEK_DIR" --pcap-ref "$(basename "$PCAP_PATH")"
else
    echo "No PCAP specified. Running synthetic sample data pipeline..."
    python scripts/run_pipeline.py --sample
fi

echo "Pipeline execution finished successfully."
