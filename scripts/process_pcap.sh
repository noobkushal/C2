#!/usr/bin/env bash
# NetWatch SOC — Zeek PCAP Processing Wrapper
# Usage: ./scripts/process_pcap.sh data/raw/<capture_name>.pcap

set -e

PCAP_PATH="$1"

if [ -z "$PCAP_PATH" ]; then
    echo "Usage: $0 <path_to_pcap>" >&2
    exit 1
fi

if [ ! -f "$PCAP_PATH" ]; then
    echo "Error: PCAP file '$PCAP_PATH' not found." >&2
    exit 1
fi

BASE_NAME=$(basename "$PCAP_PATH" | cut -f 1 -d '.')
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT_DIR="data/zeek/${BASE_NAME}_${TIMESTAMP}"

mkdir -p "$OUT_DIR"

echo "Processing ${PCAP_PATH} with Zeek into ${OUT_DIR}..."
(cd "$OUT_DIR" && zeek -r "$(realpath "../../../${PCAP_PATH}")")

echo "Zeek processing complete. Output saved to ${OUT_DIR}"
echo "${OUT_DIR}"
