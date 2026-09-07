"""
SAFE SIMULATION — NOT MALWARE. Generates regular-interval HTTP requests
to a local test server (127.0.0.1:8888) to produce beacon-like telemetry
for detector validation. No payload, no persistence, no external contact.
"""

import time
import random
import requests
import sys

def run_beacon(interval_seconds: float = 30.0, jitter_seconds: float = 1.0, count: int = 20, target: str = "http://127.0.0.1:8888"):
    print("=" * 60)
    print("SAFE SIMULATION — NOT MALWARE")
    print(f"Starting benign beacon simulator: {count} requests to {target}")
    print(f"Interval: {interval_seconds}s (jitter ±{jitter_seconds}s)")
    print("=" * 60)

    for i in range(count):
        try:
            resp = requests.get(target, timeout=2.0)
            print(f"[{i+1}/{count}] HTTP GET {target} -> Status {resp.status_code}")
        except Exception as e:
            print(f"[{i+1}/{count}] Connection failed (ensure test_server is running): {e}")

        if i < count - 1:
            sleep_time = max(0.1, interval_seconds + random.uniform(-jitter_seconds, jitter_seconds))
            time.sleep(sleep_time)

if __name__ == "__main__":
    run_beacon()
