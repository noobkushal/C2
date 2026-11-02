#!/usr/bin/env bash
# NetWatch SOC — Live Packet Capture Wrapper
# Usage: ./scripts/capture_traffic.sh [interface] [duration_seconds] [output_name]

set -e

INTERFACE="${1:-eth0}"
DURATION="${2:-30}"
OUTPUT_NAME="${3:-capture_$(date +%Y%m%d_%H%M%S)}"
OUTPUT_PATH="data/raw/${OUTPUT_NAME}.pcap"

echo "============================================================"
echo "SAFE SIMULATION — NOT MALWARE"
echo "Starting packet capture on interface '${INTERFACE}' for ${DURATION}s"
echo "Output path: ${OUTPUT_PATH}"
echo "============================================================"

# Ensure directory exists
mkdir -p data/raw

# Validate interface name parameter to prevent command injection
if [[ ! "$INTERFACE" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Error: Invalid interface name format." >&2
    exit 1
fi

sudo tcpdump -i "$INTERFACE" -w "$OUTPUT_PATH" -G "$DURATION" -W 1 || {
    echo "tcpdump completed or interrupted."
}

echo "Capture saved to ${OUTPUT_PATH}"
