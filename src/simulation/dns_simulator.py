"""
SAFE SIMULATION — NOT MALWARE
Generates synthetic DNS events for testing detection engine without making real DNS queries.
"""

import random

def generate_synthetic_domains() -> list[dict]:
    """Generates synthetic DNS domain query records."""
    domains = [
        "google.com", "github.com", "internal-ntp.local", "update.microsoft.com",
        "safesite.org", "api.github.com", "cdn.cloudflare.net"
    ]
    # Anomalous domains
    long_domain = "a" * 55 + ".c2-tunnel-beacon.org"
    dga_domain = "x92jf83kd91ls04mf8.malware-sim.test"
    
    records = []
    for d in domains:
        for _ in range(random.randint(2, 5)):
            records.append({"domain": d, "type": "normal"})
            
    records.append({"domain": long_domain, "type": "long"})
    records.append({"domain": dga_domain, "type": "rare"})
    
    # Subdomain tunneling simulation
    for i in range(8):
        records.append({"domain": f"sub{i}.exfiltration-lab.org", "type": "subdomain_tunnel"})
        
    return records
