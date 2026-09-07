"""
SAFE SIMULATION — NOT MALWARE
Generates randomized baseline HTTP noise traffic against local test server.
"""

import time
import random
import requests

def run_normal_traffic(count: int = 15, target: str = "http://127.0.0.1:8888"):
    print("=" * 60)
    print("SAFE SIMULATION — NOT MALWARE")
    print(f"Generating benign background noise traffic ({count} requests)")
    print("=" * 60)

    for i in range(count):
        try:
            resp = requests.get(target, timeout=2.0)
            print(f"[{i+1}/{count}] Normal request -> {resp.status_code}")
        except Exception:
            pass
        time.sleep(random.uniform(0.5, 3.0))

if __name__ == "__main__":
    run_normal_traffic()
