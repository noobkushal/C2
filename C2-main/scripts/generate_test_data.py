import random
import uuid
from datetime import datetime, timedelta, timezone
from src.database.database import init_db
from src.database.models import NetworkEvent, DNSEvent
from src.database.repositories import insert_network_events_batch, insert_dns_events_batch
from src.utils.logging_config import logger

def generate_all_test_data(db_path: str | None = None) -> dict[str, int]:
    """Generates synthetic network events and DNS events directly into SQLite DB."""
    init_db(db_path)
    base_time = datetime.now(timezone.utc) - timedelta(hours=4)
    
    net_events = []
    dns_events = []

    # 1. Normal Baseline Noise (~800 events across 10 internal hosts)
    internal_hosts = [f"192.168.1.{10 + i}" for i in range(10)]
    common_dsts = ["10.0.0.1", "10.0.0.2", "8.8.8.8", "1.1.1.1", "142.250.190.46"]
    common_ports = [80, 443, 53, 22, 123]
    protocols = ["tcp", "udp"]

    for _ in range(800):
        ts = (base_time + timedelta(seconds=random.randint(0, 14400))).strftime("%Y-%m-%dT%H:%M:%SZ")
        src = random.choice(internal_hosts)
        dst = random.choice(common_dsts)
        port = random.choice(common_ports)
        proto = "udp" if port in (53, 123) else "tcp"
        
        evt = NetworkEvent(
            event_id=str(uuid.uuid4()),
            timestamp=ts,
            source_ip=src,
            source_port=random.randint(49152, 65535),
            destination_ip=dst,
            destination_port=port,
            protocol=proto,
            duration=round(random.uniform(0.1, 5.0), 2),
            bytes_sent=random.randint(100, 2000),
            bytes_received=random.randint(500, 15000),
            connection_state="SF",
            log_source="conn",
            pcap_reference="sample_baseline.pcap"
        )
        net_events.append(evt)

    # 2. Clear Beaconing Pair (192.168.1.100 -> 10.0.0.99 on unusual port 8443, ~30s interval, CV < 0.05)
    beacon_start = base_time + timedelta(minutes=15)
    for i in range(30):
        # 30s interval with tiny ±0.5s jitter
        jitter = random.uniform(-0.5, 0.5)
        ts = (beacon_start + timedelta(seconds=30 * i + jitter)).strftime("%Y-%m-%dT%H:%M:%SZ")
        evt = NetworkEvent(
            event_id=f"beacon-evt-{i}",
            timestamp=ts,
            source_ip="192.168.1.100",
            source_port=52000 + i,
            destination_ip="10.0.0.99",
            destination_port=8443,
            protocol="tcp",
            duration=0.5,
            bytes_sent=512,
            bytes_received=1024,
            connection_state="SF",
            log_source="conn",
            pcap_reference="sample_c2_beacon.pcap"
        )
        net_events.append(evt)

    # 3. High-Frequency-but-Benign Case (NTP telemetry: 192.168.1.50 -> 10.0.0.1 on port 123)
    ntp_start = base_time + timedelta(minutes=30)
    for i in range(25):
        ts = (ntp_start + timedelta(seconds=i * 2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        evt = NetworkEvent(
            event_id=f"ntp-evt-{i}",
            timestamp=ts,
            source_ip="192.168.1.50",
            source_port=123,
            destination_ip="10.0.0.1",
            destination_port=123,
            protocol="udp",
            duration=0.01,
            bytes_sent=48,
            bytes_received=48,
            connection_state="SF",
            log_source="conn",
            pcap_reference="sample_baseline.pcap"
        )
        net_events.append(evt)

    # 4. Rare Destination Case (192.168.1.12 -> 192.168.99.99 on port 4444)
    rare_start = base_time + timedelta(minutes=45)
    for i in range(5):
        ts = (rare_start + timedelta(minutes=i * 5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        evt = NetworkEvent(
            event_id=f"rare-evt-{i}",
            timestamp=ts,
            source_ip="192.168.1.12",
            source_port=53000 + i,
            destination_ip="192.168.99.99",
            destination_port=4444,
            protocol="tcp",
            duration=1.2,
            bytes_sent=200,
            bytes_received=400,
            connection_state="SF",
            log_source="conn",
            pcap_reference="sample_rare.pcap"
        )
        net_events.append(evt)

    # 5. DNS Events (Normal + Long Domain + Subdomain Tunneling)
    for i in range(150):
        ts = (base_time + timedelta(seconds=random.randint(0, 14400))).strftime("%Y-%m-%dT%H:%M:%SZ")
        src = random.choice(internal_hosts)
        dom = random.choice(["google.com", "github.com", "microsoft.com", "wikipedia.org"])
        dns_events.append(DNSEvent(
            event_id=str(uuid.uuid4()),
            timestamp=ts,
            source_ip=src,
            domain=dom,
            query_type="A",
            response="93.184.216.34",
            ttl=300.0
        ))

    # Long Domain Anomalies
    long_dom = "encoded-c2-stage2-exfil-data-payload-string-0123456789.malicious-sim.org"
    for i in range(5):
        ts = (base_time + timedelta(minutes=i * 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        dns_events.append(DNSEvent(
            event_id=f"dns-long-{i}",
            timestamp=ts,
            source_ip="192.168.1.100",
            domain=long_dom,
            query_type="TXT",
            response="v=spf1 include:_spf.google.com ~all",
            ttl=60.0
        ))

    # Subdomain Tunneling Anomalies (8 distinct subdomains under base)
    for i in range(8):
        ts = (base_time + timedelta(minutes=i * 2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        dns_events.append(DNSEvent(
            event_id=f"dns-sub-{i}",
            timestamp=ts,
            source_ip="192.168.1.100",
            domain=f"chunk{i}.exfiltration-tunnel.test.org",
            query_type="A",
            response="10.0.0.99",
            ttl=30.0
        ))

    ins_net = insert_network_events_batch(net_events, db_path=db_path)
    ins_dns = insert_dns_events_batch(dns_events, db_path=db_path)
    logger.info(f"Generated test dataset: {ins_net} network events, {ins_dns} DNS events.")

    return {"net_events": ins_net, "dns_events": ins_dns}

if __name__ == "__main__":
    generate_all_test_data()
